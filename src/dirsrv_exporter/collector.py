import json
from datetime import datetime, UTC
from logging import getLogger
from typing import Iterator, Literal
from urllib.parse import urlsplit

from ldap3 import (
    Server,
    Connection,
    SUBTREE,
    Entry,
)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.dn import parse_dn, escape_rdn
from prometheus_client import Counter
from prometheus_client.core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    InfoMetricFamily,
    Metric,
)

logger = getLogger(__name__)


class Collector:
    def __init__(
        self,
        url: str,
        user=str | None,
        password=str | None,
        authentication=str | Literal["SASL"],
        sasl_mechanism=str | None,
    ):
        if urlsplit(url).scheme == "":
            raise ValueError("Server must be specified as a URL")
        self.__server = Server(host=url, connect_timeout=1)
        self.__connection: Connection | None = None
        self.__connection_user = user
        self.__connection_password = password
        self.__connection_authentication = authentication
        self.__connection_sasl_mechanism = sasl_mechanism

    def collect(self) -> Iterator[Metric]:
        mfs = MetricFamilies()

        try:
            if not self.__connection:
                logger.debug("Connecting to %r...", self.__server)
                self.__connection = Connection(
                    self.__server,
                    auto_bind=True,
                    auto_referrals=False,
                    read_only=True,
                    user=self.__connection_user,
                    password=self.__connection_password,
                    authentication=self.__connection_authentication,
                    sasl_mechanism=self.__connection_sasl_mechanism,
                )
            backend_monitor_dns = self.collect_server(self.__connection, mfs)
            self.collect_ldbm(self.__connection, mfs, backend_monitor_dns)
            self.collect_chaining(self.__connection, mfs)
            self.collect_replication(self.__connection, mfs)
        except LDAPException:
            logger.exception("LDAP error while scraping %r", self.__server)
            mfs.up.add_metric([], 0.0)
            self.__connection = None
        else:
            mfs.up.add_metric([], 1.0)

        yield from mfs.collect()

    def collect_server(self, conn, mfs) -> list[str]:
        """
        Collect server-level metrics (including disk and snmp)
        """
        conn.search(
            "cn=monitor",
            "(objectclass=extensibleobject)",
            search_scope=SUBTREE,
            attributes=["*"],
        )
        if not conn.entries:
            logger.warning("No server staistics found")
            # XXX counter
        backend_monitor_dns = []
        for entry in conn.entries:
            if entry.entry_dn == "cn=monitor":
                mfs.add_server(entry)
                for dn in entry["backendmonitordn"].values:
                    backend_monitor_dns.append(dn)
            elif entry.entry_dn == "cn=counters,cn=monitor":
                # this entry has no statistics; it's probably vestigial
                continue
            elif entry.entry_dn == "cn=disk space,cn=monitor":
                mfs.add_disk(entry)
            elif entry.entry_dn == "cn=snmp,cn=monitor":
                mfs.add_snmp(entry)
            else:
                logger.debug("Unhandled entry %r", entry.entry_dn)
                # XXX counter
        return backend_monitor_dns

    def collect_ldbm(self, conn, mfs, backend_monitor_dns) -> None:
        conn.search(
            "cn=ldbm database,cn=plugins,cn=config",
            "(|(cn=monitor)(cn=database))",
            search_scope=SUBTREE,
            attributes=["*"],
        )
        if not conn.entries:
            logger.warning("No ldbm or backend metrics found")
            # XXX counter
        for entry in conn.entries:
            if entry.entry_dn == "cn=monitor,cn=ldbm database,cn=plugins,cn=config":
                mfs.add_ldbm(entry)
            elif (
                entry.entry_dn
                == "cn=database,cn=monitor,cn=ldbm database,cn=plugins,cn=config"
            ):
                mfs.add_ldbm_db(entry)
            elif entry.entry_dn in backend_monitor_dns:
                backend_monitor_dns.remove(entry.entry_dn)
                mfs.add_backend(entry)
            else:
                logger.debug("Not collecting %r", entry.entry_dn)
                # XXX counter
        for entry in backend_monitor_dns:
            logger.warning("Missing metrics for %r", entry)
            # XXX counter

    def collect_chaining(self, conn, mfs) -> None:
        conn.search(
            "cn=chaining database,cn=plugins,cn=config",
            "(cn=monitoring)",
            search_scope=SUBTREE,
            attributes=["*"],
        )
        if not conn.entries:
            logger.debug("No chaining metrics found")
        for entry in conn.entries:
            mfs.add_chaining(entry)

    def collect_replication(self, conn, mfs) -> None:
        conn.search(
            "cn=mapping tree,cn=config",
            "(|(objectclass=nsds5replica)(objectclass=nsds5replicationagreement))",
            search_scope=SUBTREE,
            attributes=["*"],
        )
        if not conn.entries:
            logger.debug("No replication agreements found")
        for entry in conn.entries:
            if "nsds5replica" in entry["objectClass"].values:
                mfs.add_replica(entry)
            elif "nsds5replicationagreement" in entry["objectClass"].values:
                mfs.add_repl_agmt(entry)
            else:
                logger.warning("Not collecting %r", entry.entry_dn)

    @staticmethod
    def describe() -> Iterator[Metric]:
        yield from MetricFamilies().collect()


class MetricFamilies:
    """
    Holds all Metrics. Individual collect_* methods populate Metrics with sample data extracted from the provided Entries.
    """

    labels_server_info = ["version"]
    labels_disk = ["partition"]
    labels_replica = ["replica_id", "replica_root"]
    labels_replica_info = labels_replica + ["replica_type"]
    labels_repl_agmt = ["name", "root"]
    labels_backend = ["database"]
    labels_backend_dbfile = labels_backend + ["filename"]

    def __init__(self):
        self.up = GaugeMetricFamily(
            "dirsrv_up", "1 if metrics collection was successful"
        )

        self.server_info = InfoMetricFamily(
            "dirsrv_server", "", labels=self.labels_server_info
        )
        self.server_threads = GaugeMetricFamily(
            "dirsrv_server_threads",
            "Number of active threads used for handling requests",
        )
        self.server_currentconnections = GaugeMetricFamily(
            "dirsrv_server_currentconnections",
            "Number of currently open and active connections",
        )
        self.server_totalconnections = CounterMetricFamily(
            "dirsrv_server_totalconnections", "Number of connections handled"
        )
        self.server_currentconnectionsatmaxthreads = GaugeMetricFamily(
            "dirsrv_server_currentconnectionsatmaxthreads",
            "Number of connections that are currently in a max_thread state",
        )
        self.server_maxthreadsperconnhits = CounterMetricFamily(
            "maxthreadsperconnhits", "Number of times a connection hit max thread"
        )
        self.server_dtablesize = CounterMetricFamily(
            "dirsrv_server_dtablesize",
            "?Number of file descriptors available to the directory",
        )
        self.server_readwaiters = GaugeMetricFamily(
            "dirsrv_server_readwaiters",
            "Number of threads waiting to read data from a client",
        )
        self.server_opsinitiated = CounterMetricFamily(
            "dirsrv_server_opsinitiated",
            "Number of operations the server has initiated",
        )
        self.server_opscompleted = CounterMetricFamily(
            "dirsrv_server_opscompleted",
            "Number of operations the server has completed",
        )
        self.server_entriessent = CounterMetricFamily(
            "dirsrv_server_entriessent",
            "Number of entries sent to clients since the server started",
        )
        self.server_bytessent = CounterMetricFamily(
            "dirsrv_server_bytessent",
            "Number of bytes sent to clients since the server started",
        )
        self.server_currenttime = GaugeMetricFamily(
            "dirsrv_server_currenttime", "Timestamp when metrics snapshot was taken"
        )
        self.server_starttime = GaugeMetricFamily(
            "dirsrv_server_starttime", "Timestamp when instance started"
        )
        self.server_nbackends = GaugeMetricFamily(
            "dirsrv_server_nbackends", "Number of local database backends"
        )

        self.disk_size = GaugeMetricFamily(
            "dirsrv_disk_size", "Filesystem size in bytes", labels=self.labels_disk
        )
        self.disk_used = GaugeMetricFamily(
            "dirsrv_disk_used", "Filesystem used in bytes", labels=self.labels_disk
        )
        self.disk_available = GaugeMetricFamily(
            "dirsrv_disk_free",
            "Filesystem free space in bytes",
            labels=self.labels_disk,
        )

        self.snmp_anonymousbinds = CounterMetricFamily(
            "dirsrv_snmp_anonymousbinds", "Number of anonymous binds"
        )
        self.snmp_unauthbinds = CounterMetricFamily(
            "dirsrv_snmp_unauthbinds", "Number of unauthenticated binds"
        )
        self.snmp_simpleauthbinds = CounterMetricFamily(
            "dirsrv_snmp_simpleauthbinds", "Number of simple (password) binds"
        )
        self.snmp_strongauthbinds = CounterMetricFamily(
            "dirsrv_snmp_strongauthbinds", "Number of TLS/SASL binds"
        )
        self.snmp_bindsecurityerrors = CounterMetricFamily(
            "dirsrv_snmp_bindsecurityerrors",
            "Number of operations rejected due to invalid credentials or inappropriate authentication",
        )
        self.snmp_inops = CounterMetricFamily(
            "dirsrv_snmp_inops", "Number of operations forwarded to this server"
        )
        self.snmp_compareops = CounterMetricFamily(
            "dirsrv_snmp_compareops", "Number of compare operations serviced"
        )
        self.snmp_addentryops = CounterMetricFamily(
            "dirsrv_snmp_addentryops", "Number of add operations serviced"
        )
        self.snmp_removeentryops = CounterMetricFamily(
            "dirsrv_snmp_removeentryops", "Number of remove operations serviced"
        )
        self.snmp_modifyentryops = CounterMetricFamily(
            "dirsrv_snmp_modifyentryops", "Number of modify operations serviced"
        )
        self.snmp_modifyrdnops = CounterMetricFamily(
            "dirsrv_snmp_modifyrdnops",
            "Number of modify RDN modify operations serviced",
        )
        self.snmp_searchops = CounterMetricFamily(
            "dirsrv_snmp_searchops",
            "Number of search operations serviced (includes read and list operations)",
        )
        self.snmp_onelevelsearchops = CounterMetricFamily(
            "dirsrv_snmp_onelevelsearchops",
            "Number of one-level search operations serviced",
        )
        self.snmp_wholesubtreesearchops = CounterMetricFamily(
            "dirsrv_snmp_wholesubtreesearchops",
            "Number of whole-subtree search operations serviced",
        )
        self.snmp_referrals = CounterMetricFamily(
            "dirsrv_snmp_referrals",
            "Number of referrals returned in response to client requests",
        )
        self.snmp_chainings = CounterMetricFamily(
            "dirsrv_snmp_chainings",
            "Number of chainings (proxy requests) performed in response to client requests",
        )
        self.snmp_securityerrors = CounterMetricFamily(
            "dirsrv_snmp_securityerrors",
            "Number of operations forwarded to this server that did not meet security requirements",
        )
        self.snmp_errors = CounterMetricFamily(
            "dirsrv_snmp_errors",
            "Number of requests that could not be serviced due to errors (excluding security and referral errors)",
        )
        self.snmp_connections = GaugeMetricFamily(
            "dirsrv_snmp_connections", "Number of currently connected clients"
        )
        self.snmp_connectionseq = CounterMetricFamily(
            "dirsrv_snmp_connectionseq", "?Number of connections"
        )
        self.snmp_connectionsinmaxthreads = GaugeMetricFamily(
            "dirsrv_snmp_connectionsinmaxthreads",
            "Number of connections that are in max threads",
        )
        self.snmp_connectionsmaxthreadscount = CounterMetricFamily(
            "dirsrv_snmp_connectionsmaxthreadscount",
            "Number of times a connection hit max threads",
        )
        self.snmp_bytesrecv = CounterMetricFamily(
            "dirsrv_snmp_bytesrecv", "Bytes read from clients"
        )
        self.snmp_bytessent = CounterMetricFamily(
            "dirsrv_snmp_bytessent", "Bytes sent to clients"
        )
        self.snmp_entriesreturned = CounterMetricFamily(
            "dirsrv_snmp_entriesreturned", "Number of entries returned by the server"
        )
        self.snmp_referralsreturned = CounterMetricFamily(
            "dirsrv_snmp_referralsreturned",
            "Number of referrals returned by the server",
        )
        self.snmp_supplierentries = CounterMetricFamily(
            "dirsrv_snmp_supplierentries", "?"
        )
        self.snmp_cacheentries = CounterMetricFamily(
            "dirsrv_snmp_cacheentries", "Number of entries cached"
        )
        self.snmp_cachehits = CounterMetricFamily(
            "dirsrv_snmp_cachehits", "Number of operations serviced from cache"
        )
        self.snmp_consumerhits = CounterMetricFamily("dirsrv_snmp_consumerhits", "?")

        self.ldbm_dbcachehits = CounterMetricFamily(
            "dirsrv_ldbm_dbcachehits", "Number of cache lookups found in the cache"
        )
        self.ldbm_dbcachetries = CounterMetricFamily(
            "dirsrv_ldbm_dbcachetries", "Number of cache lookups"
        )
        self.ldbm_dbcachehitratio = GaugeMetricFamily(
            "dirsrv_ldbm_dbcachehitratio", "Ratio of cache hits to cache tries"
        )
        self.ldbm_dbcachepagein = CounterMetricFamily(
            "dirsrv_ldbm_dbcachepagein", "?Number of pages read in to cache"
        )
        self.ldbm_dbcachepageout = CounterMetricFamily(
            "dirsrv_ldbm_dbcachepageout", "?Number of pages written out to the cache"
        )
        self.ldbm_dbcacheroevict = CounterMetricFamily(
            "dirsrv_ldbm_dbcacheroevict",
            "?Number of clean pages evicted from the cache",
        )
        self.ldbm_dbcacherwevict = CounterMetricFamily(
            "dirsrv_ldbm_dbcacherwevict",
            "?Number of dirty pages evicted from the cache",
        )
        self.ldbm_normalizeddncachetries = CounterMetricFamily(
            "dirsrv_ldbm_normalizeddncachetries",
            "Number of Normalized DN cache lookups",
        )
        self.ldbm_normalizeddncachehits = CounterMetricFamily(
            "dirsrv_ldbm_normalizeddncachehits",
            "Number of Normalized DN cache lookups found in the cache",
        )
        self.ldbm_normalizeddncachemisses = CounterMetricFamily(
            "dirsrv_ldbm_normalizeddncachemisses",
            "Number of Normalized DN cache lookups not found within the cache",
        )
        self.ldbm_normalizeddncacheevictions = CounterMetricFamily(
            "dirsrv_ldbm_normalizeddncacheevictions",
            "Number of entries evicted from the Normalized DN Cache",
        )
        self.ldbm_currentnormalizeddncachesize = GaugeMetricFamily(
            "dirsrv_ldbm_currentnormalizeddncachesize",
            "Size of the Normalized DN cache",
        )
        self.ldbm_maxnormalizeddncachesize = GaugeMetricFamily(
            "dirsrv_ldbm_maxnormalizeddncachesize",
            "Size limit of the Normalized DN cache",
        )
        self.ldbm_currentnormalizeddncachecount = GaugeMetricFamily(
            "dirsrv_ldbm_currentnormalizeddncachecount",
            "Number of entries in the Normalized DN cache",
        )
        self.ldbm_normalizeddncachethreadsize = GaugeMetricFamily(
            "dirsrv_ldbm_normalizeddncachethreadsize", "?"
        )
        self.ldbm_normalizeddncachethreadslots = GaugeMetricFamily(
            "dirsrv_ldbm_normalizeddncachethreadslots", "?"
        )

        self.ldbm_db_abort_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_abort_rate", "Number of aborted transactions"
        )
        self.ldbm_db_active_txns = GaugeMetricFamily(
            "dirsrv_ldbm_db_active_txns", "Number of active transactions"
        )
        self.ldbm_db_cache_hit = GaugeMetricFamily(
            "dirsrv_ldbm_db_cache_hit", "Number of?"
        )
        self.ldbm_db_cache_try = GaugeMetricFamily(
            "dirsrv_ldbm_db_cache_try", "Number of?"
        )
        self.ldbm_db_cache_region_wait_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_cache_region_wait_rate",
            "?Number of times a thread was forced to wait on the region lock",
        )
        self.ldbm_db_cache_size_bytes = GaugeMetricFamily(
            "dirsrv_ldbm_db_cache_size_bytes", "Number of active transactions"
        )
        self.ldbm_db_clean_pages = GaugeMetricFamily(
            "dirsrv_ldbm_db_clean_pages", "Number of clean pages in the cache"
        )
        self.ldbm_db_commit_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_commit_rate", "Number of transactions committed"
        )
        self.ldbm_db_deadlock_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_deadlock_rate", "Number of deadlocks detected"
        )
        self.ldbm_db_dirty_pages = GaugeMetricFamily(
            "dirsrv_ldbm_db_dirty_pages", "Number of dirty pages in the cache"
        )
        self.ldbm_db_hash_buckets = GaugeMetricFamily(
            "dirsrv_ldbm_db_hash_buckets", "?"
        )
        self.ldbm_db_hash_elements_examine_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_hash_elements_examine_rate", "?"
        )
        self.ldbm_db_hash_search_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_hash_search_rate", "?"
        )
        self.ldbm_db_lock_conflicts = CounterMetricFamily(
            "dirsrv_ldbm_db_lock_conflicts", "?"
        )
        self.ldbm_db_lock_region_wait_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_lock_region_wait_rate",
            "?Number of times a thread was forced to wait on the region lock",
        )
        self.ldbm_db_lock_request_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_lock_request_rate", "?"
        )
        self.ldbm_db_lockers = GaugeMetricFamily("dirsrv_ldbm_db_lockers", "?")
        self.ldbm_db_configured_locks = GaugeMetricFamily(
            "dirsrv_ldbm_db_configured_locks", "?"
        )
        self.ldbm_db_current_locks = GaugeMetricFamily(
            "dirsrv_ldbm_db_current_locks", "?"
        )
        self.ldbm_db_max_locks = GaugeMetricFamily("dirsrv_ldbm_db_max_locks", "?")
        self.ldbm_db_current_lock_objects = GaugeMetricFamily(
            "dirsrv_ldbm_db_current_lock_objects", "?"
        )
        self.ldbm_db_max_lock_objects = GaugeMetricFamily(
            "dirsrv_ldbm_db_max_lock_objects", "?"
        )
        self.ldbm_db_log_bytes_since_checkpoint = GaugeMetricFamily(
            "dirsrv_ldbm_db_log_bytes_since_checkpoint",
            "Number of bytes written to the log since the last checkpoint",
        )
        self.ldbm_db_log_region_wait_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_log_region_wait_rate", "?"
        )
        self.ldbm_db_log_write_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_log_write_rate", "?"
        )
        self.ldbm_db_longest_chain_length = GaugeMetricFamily(
            "dirsrv_ldbm_db_longest_chain_length",
            "Longest chain encountered in buffer hash table lookups",
        )
        self.ldbm_db_page_create_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_create_rate", ""
        )
        self.ldbm_db_page_read_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_read_rate", ""
        )
        self.ldbm_db_page_ro_evict_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_ro_evict_rate", ""
        )
        self.ldbm_db_page_rw_evict_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_rw_evict_rate", ""
        )
        self.ldbm_db_page_trickle_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_trickle_rate", ""
        )
        self.ldbm_db_page_write_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_page_write_rate", ""
        )
        self.ldbm_db_pages_in_use = GaugeMetricFamily("dirsrv_ldbm_db_pages_in_use", "")
        self.ldbm_db_txn_region_wait_rate = CounterMetricFamily(
            "dirsrv_ldbm_db_txn_region_wait_rate", ""
        )
        self.ldbm_db_mp_pagesize = GaugeMetricFamily("dirsrv_ldbm_db_mp_pagesize", "")

        self.backend_readonly = GaugeMetricFamily(
            "dirsrv_backend_readonly",
            "1 if the backend is read-only",
            labels=self.labels_backend,
        )
        self.backend_entrycachehits = CounterMetricFamily(
            "dirsrv_backend_entrycachehits", "?", labels=self.labels_backend
        )
        self.backend_entrycachetries = CounterMetricFamily(
            "dirsrv_backend_entrycacheries", "?", labels=self.labels_backend
        )
        # entrycachehitratio is redundant
        self.backend_currententrycachesize = GaugeMetricFamily(
            "dirsrv_backend_currententrycachesize", "?", labels=self.labels_backend
        )
        self.backend_maxentrycachesize = GaugeMetricFamily(
            "dirsrv_backend_maxentrycachesize", "?", labels=self.labels_backend
        )
        self.backend_currententrycachecount = GaugeMetricFamily(
            "dirsrv_backend_currententrycachecount", "?", labels=self.labels_backend
        )
        self.backend_maxentrycachecount = GaugeMetricFamily(
            "dirsrv_backend_maxentrycachecount", "?", labels=self.labels_backend
        )
        self.backend_dncachehits = GaugeMetricFamily(
            "dirsrv_backend_dncachehits", "?", labels=self.labels_backend
        )
        self.backend_dncachetries = GaugeMetricFamily(
            "dirsrv_backend_dncachetries", "?", labels=self.labels_backend
        )
        # dncachehitratio: is redundant
        self.backend_currentdncachesize = GaugeMetricFamily(
            "dirsrv_backend_currentdncachesize", "?", labels=self.labels_backend
        )
        self.backend_maxdncachesize = GaugeMetricFamily(
            "dirsrv_backend_maxdncachesize", "?", labels=self.labels_backend
        )
        self.backend_currentdncachecount = GaugeMetricFamily(
            "dirsrv_backend_currentcachecount", "?", labels=self.labels_backend
        )
        self.backend_maxdncachecount = GaugeMetricFamily(
            "dirsrv_backend_maxdncachecount", "?", labels=self.labels_backend
        )
        self.backend_dbfile_cachehit = GaugeMetricFamily(
            "dirsrv_backend_dbfile_cachehit", "?", labels=self.labels_backend_dbfile
        )
        self.backend_dbfile_cachemiss = GaugeMetricFamily(
            "dirsrv_backend_dbfile_cachemiss", "?", labels=self.labels_backend_dbfile
        )
        self.backend_dbfile_pagein = GaugeMetricFamily(
            "dirsrv_backend_dbfile_pagein", "?", labels=self.labels_backend_dbfile
        )
        self.backend_dbfile_pageout = GaugeMetricFamily(
            "dirsrv_backend_dbfile_pageout", "?", labels=self.labels_backend_dbfile
        )

        self.replica_info = InfoMetricFamily(
            "dirsrv_replica", "", labels=self.labels_replica_info
        )
        self.replica_change_count = GaugeMetricFamily(
            "dirsrv_replica_change_count",
            "?Total number of entries in the changelog which remain to be replicated",
            labels=self.labels_replica,
        )

        self.repl_agmt_status = GaugeMetricFamily(
            "dirsrv_replication_agreeement_status",
            "?",
            labels=self.labels_repl_agmt + ["state"],
        )
        self.repl_agmt_changes_replayed = CounterMetricFamily(
            "dirsrv_replication_agreement_changes_replayed",
            "Number of changes supplied to consumer and replayed",
            labels=self.labels_repl_agmt + ["replica_id"],
        )
        self.repl_agmt_changes_skipped = CounterMetricFamily(
            "dirsrv_replication_agreement_changes_skipped",
            "Number of changes supplied to consumer and skipped",
            labels=self.labels_repl_agmt + ["replica_id"],
        )
        self.repl_agmt_update_start = GaugeMetricFamily(
            "dirsrv_replication_agreement_update_start_timestamp",
            "When the most recent replication update started",
            labels=self.labels_repl_agmt,
        )
        self.repl_agmt_update_end = GaugeMetricFamily(
            "dirsrv_replication_agreement_update_end_timestamp",
            "When the most recent replication update ended",
            labels=self.labels_repl_agmt,
        )

    def collect(self) -> Iterator[Metric]:
        for attr in dir(self):
            value = getattr(self, attr)
            if isinstance(value, Metric):
                yield value

    def add_server(self, entry: Entry) -> None:
        """
        Corresponds to 'dsconf INSTANCE monitor server'
        <https://docs.redhat.com/en/documentation/red_hat_directory_server/12/html/configuration_and_schema_reference/assembly_cn-monitor_config-schema-reference-title>
        """
        self.server_info.add_metric(
            self.labels_server_info, {"version": entry["version"].value}
        )
        self.server_threads.add_metric([], float(entry["threads"].value))
        self.server_currentconnections.add_metric(
            [], float(entry["currentconnections"].value)
        )
        self.server_totalconnections.add_metric(
            [], float(entry["currentconnections"].value)
        )
        self.server_currentconnectionsatmaxthreads.add_metric(
            [], float(entry["currentconnectionsatmaxthreads"].value)
        )
        self.server_maxthreadsperconnhits.add_metric(
            [], float(entry["maxthreadsperconnhits"].value)
        )
        self.server_dtablesize.add_metric([], float(entry["dtablesize"].value))
        self.server_readwaiters.add_metric([], float(entry["readwaiters"].value))
        self.server_opsinitiated.add_metric([], float(entry["opsinitiated"].value))
        self.server_opscompleted.add_metric([], float(entry["opscompleted"].value))
        self.server_entriessent.add_metric([], float(entry["entriessent"].value))
        self.server_bytessent.add_metric([], float(entry["bytessent"].value))
        self.server_currenttime.add_metric(
            [], self.parse_ldap_timestamp(entry["currenttime"].value).timestamp()
        )
        self.server_starttime.add_metric(
            [], self.parse_ldap_timestamp(entry["starttime"].value).timestamp()
        )
        self.server_nbackends.add_metric([], float(entry["nbackends"].value))

    def add_disk(self, entry: Entry) -> None:
        """
        Corresponds to 'dsconf INSTANCE monitor disk'
        """
        for value in entry["dsdisk"].values:
            partition, size, used, available = None, None, None, None
            for subattrvalue in value.split(" "):
                subattr, sep, subvalue = subattrvalue.partition("=")
                if not sep:
                    logger.warning(
                        "Couldn't parse dsdisk subattrvalue %r", subattrvalue
                    )
                    # XXX counter
                    continue

                if subattr == "partition":
                    partition = subvalue[1:-1]
                elif subattr == "size":
                    size = float(subvalue[1:-1])
                elif subattr == "used":
                    used = float(subvalue[1:-1])
                elif subattr == "available":
                    available = float(subvalue[1:-1])
                elif subattr == "use%":
                    pass  # Redundant
                else:
                    logger.warning(
                        "Ignoring unknown subattr %r from dsdisk attribute %r",
                        subattr,
                        value,
                    )
                    # XXX counter

            if partition and size:
                self.disk_size.add_metric([partition], size)
            if partition and used:
                self.disk_used.add_metric([partition], used)
            if partition and available:
                self.disk_available.add_metric([partition], available)

    def add_snmp(self, entry: Entry) -> None:
        """
        Corresponds to 'dsconf INSTANCE monitor snmp'
        <https://docs.redhat.com/en/documentation/red_hat_directory_server/11/html/administration_guide/monitoring_ds_using_snmp#Monitoring_DS_Using_SNMP-Using_the_Management_Information_Base>
        """
        self.snmp_anonymousbinds.add_metric([], float(entry["anonymousbinds"].value))
        self.snmp_unauthbinds.add_metric([], float(entry["unauthbinds"].value))
        self.snmp_simpleauthbinds.add_metric([], float(entry["simpleauthbinds"].value))
        self.snmp_strongauthbinds.add_metric([], float(entry["strongauthbinds"].value))
        self.snmp_bindsecurityerrors.add_metric(
            [], float(entry["bindsecurityerrors"].value)
        )
        self.snmp_inops.add_metric([], float(entry["inops"].value))
        self.snmp_compareops.add_metric([], float(entry["compareops"].value))
        self.snmp_addentryops.add_metric([], float(entry["addentryops"].value))
        self.snmp_removeentryops.add_metric([], float(entry["removeentryops"].value))
        self.snmp_modifyentryops.add_metric([], float(entry["modifyentryops"].value))
        self.snmp_modifyrdnops.add_metric([], float(entry["modifyrdnops"].value))
        # readops is always 0, so not included
        # listops is always 0, so not included
        self.snmp_searchops.add_metric([], float(entry["searchops"].value))
        self.snmp_onelevelsearchops.add_metric(
            [], float(entry["onelevelsearchops"].value)
        )
        self.snmp_wholesubtreesearchops.add_metric(
            [], float(entry["wholesubtreesearchops"].value)
        )
        self.snmp_referrals.add_metric([], float(entry["referrals"].value))
        self.snmp_chainings.add_metric([], float(entry["chainings"].value))
        self.snmp_securityerrors.add_metric([], float(entry["securityerrors"].value))
        self.snmp_errors.add_metric([], float(entry["errors"].value))
        self.snmp_connections.add_metric([], float(entry["connections"].value))
        self.snmp_connectionseq.add_metric([], float(entry["connectionseq"].value))
        self.snmp_connectionsinmaxthreads.add_metric(
            [], float(entry["connectionsinmaxthreads"].value)
        )
        self.snmp_connectionsmaxthreadscount.add_metric(
            [], float(entry["connectionsmaxthreadscount"].value)
        )
        self.snmp_bytesrecv.add_metric([], float(entry["bytesrecv"].value))
        self.snmp_bytessent.add_metric([], float(entry["bytessent"].value))
        self.snmp_entriesreturned.add_metric([], float(entry["entriesreturned"].value))
        self.snmp_referralsreturned.add_metric(
            [], float(entry["referralsreturned"].value)
        )
        self.snmp_supplierentries.add_metric([], float(entry["supplierentries"].value))
        self.snmp_cacheentries.add_metric([], float(entry["cacheentries"].value))
        self.snmp_cachehits.add_metric([], float(entry["cachehits"].value))
        self.snmp_consumerhits.add_metric([], float(entry["consumerhits"].value))

    def add_ldbm(self, entry: Entry) -> None:
        """
        Corresponds to 'dsconf INSTANCE monitor ldbm'
        https://docs.redhat.com/en/documentation/red_hat_directory_server/12/html/configuration_and_schema_reference/plug_in_implemented_server_functionality_reference#assembly_database-attributes-under-cn-monitor-cn-ldbm-database-cn-plugins-cn-config_assembly_database-plug-in-attributes
        """
        self.ldbm_dbcachehits.add_metric([], float(entry["dbcachehits"].value))
        self.ldbm_dbcachetries.add_metric([], float(entry["dbcachetries"].value))
        self.ldbm_dbcachehitratio.add_metric([], float(entry["dbcachehitratio"].value))
        self.ldbm_dbcachepagein.add_metric([], float(entry["dbcachepagein"].value))
        self.ldbm_dbcachepageout.add_metric([], float(entry["dbcachepageout"].value))
        self.ldbm_dbcacheroevict.add_metric([], float(entry["dbcacherwevict"].value))
        self.ldbm_dbcacherwevict.add_metric([], float(entry["dbcacherwevict"].value))
        self.ldbm_normalizeddncachetries.add_metric(
            [], float(entry["normalizeddncachetries"].value)
        )
        self.ldbm_normalizeddncachehits.add_metric(
            [], float(entry["normalizeddncachehits"].value)
        )
        self.ldbm_normalizeddncachemisses.add_metric(
            [], float(entry["normalizeddncachemisses"].value)
        )
        self.ldbm_normalizeddncacheevictions.add_metric(
            [], float(entry["normalizeddncacheevictions"].value)
        )
        self.ldbm_currentnormalizeddncachesize.add_metric(
            [], float(entry["currentnormalizeddncachesize"].value)
        )
        self.ldbm_maxnormalizeddncachesize.add_metric(
            [], float(entry["maxnormalizeddncachesize"].value)
        )
        self.ldbm_currentnormalizeddncachecount.add_metric(
            [], float(entry["currentnormalizeddncachecount"].value)
        )
        self.ldbm_normalizeddncachethreadsize.add_metric(
            [], float(entry["normalizeddncachethreadsize"].value)
        )
        self.ldbm_normalizeddncachethreadslots.add_metric(
            [], float(entry["normalizeddncachethreadslots"].value)
        )

    def add_ldbm_db(self, entry: Entry) -> None:
        """
        Additional attributes output by 'dsconf INSTANCE monitor ldbm', but
        which come from the sub-entry 'cn=database'.
        """
        self.ldbm_db_abort_rate.add_metric(
            [], float(entry["nsslapd-db-abort-rate"].value)
        )
        self.ldbm_db_active_txns.add_metric(
            [], float(entry["nsslapd-db-active-txns"].value)
        )
        self.ldbm_db_cache_hit.add_metric(
            [], float(entry["nsslapd-db-cache-hit"].value)
        )
        self.ldbm_db_cache_try.add_metric(
            [], float(entry["nsslapd-db-cache-try"].value)
        )
        self.ldbm_db_cache_region_wait_rate.add_metric(
            [], float(entry["nsslapd-db-cache-region-wait-rate"].value)
        )
        self.ldbm_db_cache_size_bytes.add_metric(
            [], float(entry["nsslapd-db-cache-size-bytes"].value)
        )
        self.ldbm_db_clean_pages.add_metric(
            [], float(entry["nsslapd-db-clean-pages"].value)
        )
        self.ldbm_db_commit_rate.add_metric(
            [], float(entry["nsslapd-db-commit-rate"].value)
        )
        self.ldbm_db_deadlock_rate.add_metric(
            [], float(entry["nsslapd-db-deadlock-rate"].value)
        )
        self.ldbm_db_dirty_pages.add_metric(
            [], float(entry["nsslapd-db-dirty-pages"].value)
        )
        self.ldbm_db_hash_buckets.add_metric(
            [], float(entry["nsslapd-db-hash-buckets"].value)
        )
        self.ldbm_db_hash_elements_examine_rate.add_metric(
            [], float(entry["nsslapd-db-hash-elements-examine-rate"].value)
        )
        self.ldbm_db_hash_search_rate.add_metric(
            [], float(entry["nsslapd-db-hash-search-rate"].value)
        )
        self.ldbm_db_lock_conflicts.add_metric(
            [], float(entry["nsslapd-db-lock-conflicts"].value)
        )
        self.ldbm_db_lock_region_wait_rate.add_metric(
            [], float(entry["nsslapd-db-lock-region-wait-rate"].value)
        )
        self.ldbm_db_lock_request_rate.add_metric(
            [], float(entry["nsslapd-db-lock-request-rate"].value)
        )
        self.ldbm_db_lockers.add_metric([], float(entry["nsslapd-db-lockers"].value))
        self.ldbm_db_configured_locks.add_metric(
            [], float(entry["nsslapd-db-configured-locks"].value)
        )
        self.ldbm_db_current_locks.add_metric(
            [], float(entry["nsslapd-db-current-locks"].value)
        )
        self.ldbm_db_max_locks.add_metric(
            [], float(entry["nsslapd-db-max-locks"].value)
        )
        self.ldbm_db_current_lock_objects.add_metric(
            [], float(entry["nsslapd-db-current-lock-objects"].value)
        )
        self.ldbm_db_max_lock_objects.add_metric(
            [], float(entry["nsslapd-db-max-lock-objects"].value)
        )
        self.ldbm_db_log_bytes_since_checkpoint.add_metric(
            [], float(entry["nsslapd-db-log-bytes-since-checkpoint"].value)
        )
        self.ldbm_db_log_region_wait_rate.add_metric(
            [], float(entry["nsslapd-db-log-region-wait-rate"].value)
        )
        self.ldbm_db_log_write_rate.add_metric(
            [], float(entry["nsslapd-db-log-write-rate"].value)
        )
        self.ldbm_db_longest_chain_length.add_metric(
            [], float(entry["nsslapd-db-longest-chain-length"].value)
        )
        self.ldbm_db_page_create_rate.add_metric(
            [], float(entry["nsslapd-db-page-create-rate"].value)
        )
        self.ldbm_db_page_read_rate.add_metric(
            [], float(entry["nsslapd-db-page-read-rate"].value)
        )
        self.ldbm_db_page_ro_evict_rate.add_metric(
            [], float(entry["nsslapd-db-page-ro-evict-rate"].value)
        )
        self.ldbm_db_page_rw_evict_rate.add_metric(
            [], float(entry["nsslapd-db-page-rw-evict-rate"].value)
        )
        self.ldbm_db_page_trickle_rate.add_metric(
            [], float(entry["nsslapd-db-page-trickle-rate"].value)
        )
        self.ldbm_db_page_write_rate.add_metric(
            [], float(entry["nsslapd-db-page-write-rate"].value)
        )
        self.ldbm_db_pages_in_use.add_metric(
            [], float(entry["nsslapd-db-pages-in-use"].value)
        )
        self.ldbm_db_txn_region_wait_rate.add_metric(
            [], float(entry["nsslapd-db-txn-region-wait-rate"].value)
        )
        self.ldbm_db_mp_pagesize.add_metric(
            [], float(entry["nsslapd-db-mp-pagesize"].value)
        )

    def add_backend(self, entry: Entry) -> None:
        """
        Corresponds to 'dsconf INSTANCE monitor backend'
        https://docs.redhat.com/en/documentation/red_hat_directory_server/12/html/configuration_and_schema_reference/plug_in_implemented_server_functionality_reference#assembly_database-attributes-under-cn-monitor-cn-database_name-cn-ldbm-database-cn-plugins-cn-config_assembly_database-plug-in-attributes
        """
        backend_rdn = parse_dn(entry.entry_dn)[1]
        if not (backend_rdn[0] == "cn" and backend_rdn[2] == ","):
            logger.warning("Not collecting %r", entry.entry_dn)
            return
            # XXX counter

        backend_labels = [backend_rdn[1]]

        self.backend_readonly.add_metric(backend_labels, float(entry["readonly"].value))
        self.backend_entrycachehits.add_metric(
            backend_labels, float(entry["entrycachehits"].value)
        )
        self.backend_entrycachetries.add_metric(
            backend_labels, float(entry["entrycachetries"].value)
        )
        # entrycachehitratio is redundant
        self.backend_currententrycachesize.add_metric(
            backend_labels, float(entry["currententrycachesize"].value)
        )
        self.backend_maxentrycachesize.add_metric(
            backend_labels, float(entry["maxentrycachesize"].value)
        )
        self.backend_currententrycachecount.add_metric(
            backend_labels, float(entry["currententrycachecount"].value)
        )
        self.backend_maxentrycachecount.add_metric(
            backend_labels, float(entry["maxentrycachecount"].value)
        )
        self.backend_dncachehits.add_metric(
            backend_labels, float(entry["dncachehits"].value)
        )
        self.backend_dncachetries.add_metric(
            backend_labels, float(entry["dncachetries"].value)
        )
        # dncachehitratio is redundant
        self.backend_currentdncachesize.add_metric(
            backend_labels, float(entry["currentdncachesize"].value)
        )
        self.backend_maxdncachesize.add_metric(
            backend_labels, float(entry["maxdncachesize"].value)
        )
        self.backend_currentdncachecount.add_metric(
            backend_labels, float(entry["currentdncachecount"].value)
        )
        self.backend_maxdncachecount.add_metric(
            backend_labels, float(entry["maxdncachecount"].value)
        )

        dbfilenames = {}
        for attribute in entry:
            key_prefix, sep, index = attribute.key.partition("-")
            if not sep:
                continue
            if key_prefix == "dbfilename":
                dbfilenames[int(index)] = attribute.value

        for attribute in entry:
            key_prefix, sep, index = attribute.key.partition("-")
            if not sep:
                continue
            elif key_prefix == "dbfilename":
                continue

            dbfilename = dbfilenames.get(int(index), None)
            if not dbfilename:
                logger.warning(
                    "Missing dbfilename for attribute %r of entry %r",
                    attribute,
                    entry.entry_dn,
                )
                # XXX counter
                continue

            backend_db_labels = backend_labels + [dbfilename]
            if key_prefix == "dbfilecachehit":
                mf = self.backend_dbfile_cachehit
            elif key_prefix == "dbfilecachemiss":
                mf = self.backend_dbfile_cachemiss
            elif key_prefix == "dbfilepagein":
                mf = self.backend_dbfile_pagein
            elif key_prefix == "dbfilepageout":
                mf = self.backend_dbfile_pageout
            else:
                mf = None

            if mf:
                mf.add_metric(backend_db_labels, float(entry[attribute.key].value))
            else:
                logger.warning(
                    "Ignoring unrecognized attribute %r of entry %r",
                    attribute,
                    entry.entry_dn,
                )
                # XXX counter

    def add_chaining(self, entry: Entry) -> None:
        """
        https://docs.redhat.com/en/documentation/red_hat_directory_server/12/html/configuration_and_schema_reference/plug_in_implemented_server_functionality_reference#ref_nsabandoncount_assembly_database-link-attributes-under-cn-monitoring-cn-database_link_name-cn-chaining-database-cn-plugins-cn-config
        """
        logger.warning("Not collecting %r", entry.entry_db)

    def add_replica(self, entry: Entry) -> None:
        replica_info = [
            str(entry["nsDS5ReplicaId"].value),
            str(entry["nsDS5ReplicaRoot"].value),
        ]
        self.replica_info.add_metric(
            self.labels_replica_info,
            dict(
                zip(
                    self.labels_replica_info,
                    replica_info + [str(entry["nsDS5ReplicaType"].value)],
                )
            ),
        )
        self.replica_change_count.add_metric(
            replica_info, float(entry["nsds5ReplicaChangeCount"].value)
        )

    def add_repl_agmt(self, entry: Entry) -> None:
        status_json = json.loads(entry["nsds5replicalastupdatestatusjson"].value)
        for state in ["green", "amber", "red"]:
            self.repl_agmt_status.add_metric(
                [entry["cn"].value, entry["nsds5replicaroot"].value, state],
                1 if status_json["state"] == state else 0,
            )

        changes_sent_since_startup = entry[
            "nsds5replicaChangesSentSinceStartup"
        ].value.decode("ascii")
        for changes_sent in changes_sent_since_startup.strip().split(" "):
            replica_id, sep1, rest = changes_sent.partition(":")
            replayed, sep2, skipped = rest.partition("/")
            if not sep1 or not sep2:
                logger.warning(
                    "Could not parse changes sent statistics from entry %r attribute %r",
                    entry.entry_dn,
                    changes_sent,
                )
                # XXX counter
                continue
            self.repl_agmt_changes_replayed.add_metric(
                [
                    entry["cn"].value,
                    entry["nsds5replicaroot"].value,
                    replica_id,
                ],
                float(replayed),
            )
            self.repl_agmt_changes_skipped.add_metric(
                [
                    entry["cn"].value,
                    entry["nsds5replicaroot"].value,
                    replica_id,
                ],
                float(skipped),
            )
        self.repl_agmt_update_start.add_metric(
            [entry["cn"].value, entry["nsds5replicaroot"].value, replica_id],
            float(entry["nsds5replicaLastUpdateStart"].value.timestamp()),
        )
        self.repl_agmt_update_end.add_metric(
            [entry["cn"].value, entry["nsds5replicaroot"].value, replica_id],
            float(entry["nsds5replicaLastUpdateEnd"].value.timestamp()),
        )

    @staticmethod
    def parse_ldap_timestamp(ts: str) -> datetime:
        return datetime.strptime(ts, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
