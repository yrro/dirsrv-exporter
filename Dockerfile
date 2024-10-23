FROM registry.access.redhat.com/ubi9/ubi-minimal AS builder

RUN microdnf -y install gcc python3.12 python3.12-devel systemd-devel && microdnf clean all

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/

WORKDIR /opt/app-root/src

COPY pyproject.toml uv.lock README.md src .

ENV \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never \
  UV_PYTHON=python3.12 \
  UV_PROJECT_ENVIRONMENT=/opt/app-root/venv

RUN uv sync --no-python-downloads --no-dev --no-editable --locked


FROM registry.access.redhat.com/ubi9/ubi-minimal

RUN microdnf -y install python3.12 && microdnf clean all

COPY --from=builder /opt/app-root/venv /opt/app-root/venv

ENTRYPOINT /opt/app-root/venv/bin/dirsrv-exporter

USER 65535

# vim: ts=8 sts=2 sw=2 et
