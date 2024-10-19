import faulthandler
import logging
import os
import signal
import sys

from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY
from systemd import daemon, journal

from .collector import Collector
from .threading import set_name

logger = logging.getLogger(__name__)


def main() -> int:
    faulthandler.enable()
    faulthandler.register(signal.SIGUSR1, all_threads=True)
    sys.excepthook = excepthook
    configure_logging()
    return main2(sys.argv)


def excepthook(exc_type, exc_value, exc_traceback):
    logger.critical(
        "Unhandled exception:", exc_info=(exc_type, exc_value, exc_traceback)
    )


def configure_logging():
    level = os.environ.get(
        "389_DS_EXPORTER_LOG_LEVEL", "debug" if sys.flags.dev_mode else "info"
    )

    if os.environ.get("389_DS_EXPORTER_LOG_HANDLER", "").lower() == "journal":
        handlers = [journal.JournalHandler(SYSLOG_IDENTIFIER="certmonger-exporter")]
    else:
        handlers = None

    logging.basicConfig(
        level=level.upper(),
        handlers=handlers,
        format="%(message)s",
    )
    logging.captureWarnings(True)


def main2(argv):
    def sigterm(signum, frame):
        daemon.notify("STOPPING=1")
        server.shutdown()

    signal.signal(signal.SIGTERM, sigterm)

    collector = Collector(
        url=os.environ["389_DS_EXPORTER_URL"],
        user=os.environ.get("389_DS_EXPORTER_USER"),
        password=os.environ.get("389_DS_EXPORTER_PASSWORD"),
        authentication=os.environ.get("389_DS_EXPORTER_AUTHENTICATION"),
        sasl_mechanism=os.environ.get("389_DS_EXPORTER_SASL_MECHANISM"),
    )
    REGISTRY.register(collector)
    addr = os.environ.get("389_DS_EXPORTER_ADDR", "0.0.0.0")
    port = int(os.environ.get("389_DS_EXPORTER_PORT", "9976"))
    server, thread = start_http_server(addr=addr, port=port, registry=REGISTRY)
    try:
        logger.info("Listening on %r", server.socket.getsockname())
        set_name(thread, "httpd")
        daemon.notify("READY=1")
        thread.join()
    finally:
        server.server_close()
