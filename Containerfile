# Thanks to turing85 for the inspiration for how to use ubi-micro within a Containerfile!
# <https://gist.github.com/turing85/7c450dd048fcf2ed94fed8ad5cdc5d9f>

ARG RELEASEVER=9

ARG PYTHON_VERSION=3.12


# --- Extract ubi-micro at /mnt and install python
FROM registry.access.redhat.com/ubi${RELEASEVER}/ubi AS build0

ARG RELEASEVER

ARG UPGRADE=0

COPY --from=registry.access.redhat.com/ubi${RELEASEVER}/ubi-micro / /mnt

ARG PYTHON_VERSION

RUN if [[ $UPGRADE -ge 1 ]]; then dnf --installroot=/mnt --releasever=${RELEASEVER} -y --setopt=install_weak_deps=0 --nodocs upgrade; fi

RUN dnf --installroot=/mnt --releasever=${RELEASEVER} -y --setopt=install_weak_deps=0 --nodocs install python${PYTHON_VERSION}

RUN dnf --installroot=/mnt --releasever=${RELEASEVER} -y --setopt=install_weak_deps=0 --nodocs clean all


# -- Install dependencies & app
FROM build0 AS build1

ARG PYTHON_VERSION

COPY --from=ghcr.io/astral-sh/uv:latest /uv /mnt/usr/local/bin/

COPY pyproject.toml uv.lock README.md src /mnt/opt/app-root/src/

RUN cp /etc/resolv.conf /mnt/etc/

RUN chroot /mnt \
  /usr/bin/env \
    -C /opt/app-root/src \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=python${PYTHON_VERSION} \
    UV_PROJECT_ENVIRONMENT=/opt/app-root/venv \
    uv sync --no-dev --no-editable --frozen


# --- Remove unwanted RPMs
FROM build0 AS build2

ARG PYTHON_VERSION

RUN rpm --root=/mnt --erase --allmatches --nodeps --noscripts --notriggers -vh \
  alternatives \
  bash \
  bzip2-libs \
  ca-certificates \
  coreutils-single \
  expat \
  gawk \
  gdbm-libs \
  glibc-minimal-langpack \
  gmp \
  grep \
  keyutils-libs \
  krb5-libs \
  libacl \
  libattr \
  libcap \
  libcom_err \
  libgcc \
  libsigsegv \
  libnsl2 \
  libtasn1 \
  libselinux \
  libsepol \
  libtirpc \
  libuuid \
  libverto \
  libxcrypt \
  openssl-fips-provider \
  mpdecimal \
  mpfr \
  ncurses-base \
  ncurses-libs \
  p11-kit \
  p11-kit-trust \
  pcre \
  pcre2 \
  pcre2-syntax \
  python${PYTHON_VERSION}-pip-wheel \
  readline \
  sed \
  sqlite-libs \
  tzdata \
  xz-libs

RUN rpm --root=/mnt -qa --queryformat='%{size}\t%{name}\n' | sort -n


# -- Construct final image
FROM scratch

COPY --from=build1 /mnt/opt/app-root/venv /opt/app-root/venv

COPY --from=build2 /mnt /

ENV \
  PYTHONUNBUFFERED=1 \
  PYTHONFAULTHANDLER=1

ENTRYPOINT ["/opt/app-root/venv/bin/dirsrv-exporter"]

USER 65535

EXPOSE 9976/tcp

# vim: ts=8 sts=2 sw=2 et
