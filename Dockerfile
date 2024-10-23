FROM registry.access.redhat.com/ubi9/ubi-minimal AS builder

RUN microdnf -y install gcc python3.12 python3.12-devel systemd-devel && microdnf clean all

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/

WORKDIR /opt/app-root/src

COPY pyproject.toml uv.lock README.md src .

RUN UV_PROJECT_ENVIRONMENT=/opt/app-root/venv uv sync --no-python-downloads --no-dev --no-editable --frozen


FROM registry.access.redhat.com/ubi9/ubi-minimal

RUN microdnf -y install python3.12 && microdnf clean all

COPY --from=builder /opt/app-root/venv /opt/app-root/venv

ENTRYPOINT /opt/app-root/venv/bin/dirsrv-exporter
