ARG PYTHON_VERSION=3.12

FROM registry.access.redhat.com/ubi9/ubi-minimal AS builder

ARG PYTHON_VERSION

RUN microdnf -y --setopt=install_weak_deps=0 --nodocs install python${PYTHON_VERSION} && microdnf clean all

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/

WORKDIR /opt/app-root/src

COPY pyproject.toml uv.lock README.md src .

ENV \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never \
  UV_PYTHON=python${PYTHON_VERSION} \
  UV_PROJECT_ENVIRONMENT=/opt/app-root/venv

RUN uv sync --no-python-downloads --no-dev --no-editable --frozen


FROM registry.access.redhat.com/ubi9/ubi-minimal

ARG PYTHON_VERSION

RUN microdnf -y --setopt=install_weak_deps=0 --nodocs install python${PYTHON_VERSION} && microdnf clean all

COPY --from=builder /opt/app-root/venv /opt/app-root/venv

ENTRYPOINT /opt/app-root/venv/bin/dirsrv-exporter

USER 65535

# vim: ts=8 sts=2 sw=2 et
