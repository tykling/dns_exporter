#syntax=docker/dockerfile:1.5.2
FROM cgr.dev/chainguard/python:3.11.2-r0-dev AS builder
# switch to root to install deps
USER root
RUN apk add -U --no-cache --purge --clean-protected -l -u \
    git \
    openssl-dev
# switch back to nonroot for package build
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot . .
RUN pip install .

FROM cgr.dev/chainguard/python:3.11.2-r0 AS runtime
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
ENTRYPOINT [ "/home/nonroot/.local/bin/dns_exporter" ]
