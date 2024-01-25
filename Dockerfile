#syntax=docker/dockerfile:1.6.0
FROM python:3.12.1-alpine3.19 AS builder
RUN apk add -U --no-cache --purge --clean-protected -l -u \
    alpine-sdk \
    libbsd-dev \
    openssl-dev
RUN adduser --system nonroot
# switch back to nonroot for package build
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot . .
# create empty config
RUN touch dns_exporter.yml
# install dns_exporter
RUN pip install .

FROM scratch AS tmp
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
COPY --from=builder /home/nonroot/dns_exporter.yml /home/nonroot/dns_exporter.yml

FROM python:3.12.1-alpine3.19 AS runtime
RUN adduser --system nonroot
COPY --from=tmp --chown=nonroot:nonroot /home/nonroot /home/nonroot
EXPOSE 15353
USER nonroot
CMD [ "/home/nonroot/.local/bin/dns_exporter", "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
