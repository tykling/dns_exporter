#syntax=docker/dockerfile:1.5.2
FROM cgr.dev/chainguard/python:3.11.3-r0-dev AS builder
# switch to root to install deps
USER root
RUN apk add -U --no-cache --purge --clean-protected -l -u \
    git \
    openssl-dev
# switch back to nonroot for package build
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot . .
RUN touch dns_exporter.yml; \
    pip install .

FROM scratch AS tmp
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
COPY --from=builder /home/nonroot/dns_exporter.yml /home/nonroot/dns_exporter.yml

FROM cgr.dev/chainguard/python:3.11.3-r0 AS runtime
COPY --from=tmp / /
EXPOSE 15353
CMD [ "/home/nonroot/.local/bin/dns_exporter", "-c", "/home/nonroot/dns_exporter.yml" ]
