#syntax=docker/dockerfile:1
FROM python:3.12-alpine@sha256:e75de178bc15e72f3f16bf75a6b484e33d39a456f03fc771a2b3abb9146b75f8 AS builder
# install dependenciess for building package
RUN \
apk add -U --purge --clean-protected -l -u --no-cache \
  alpine-sdk \
  cargo \
  libbsd-dev \
  libffi-dev \
  openssl-dev
# copy source
COPY / /src
# install dns_exporter
RUN pip install --user /src
# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

# create tmp container for copying files
FROM scratch AS tmp
# copy dns_exporter and dependencies
COPY --from=builder /root/.local /home/nonroot/.local
# copy example config
COPY --from=builder /src/src/dns_exporter/dns_exporter_example.yml /home/nonroot/dns_exporter.yml

FROM python:3.12-alpine@sha256:e75de178bc15e72f3f16bf75a6b484e33d39a456f03fc771a2b3abb9146b75f8 AS runtime
RUN <<EOF
# add nonroot group
addgroup -g 65532 -S nonroot
# add nonroot user
adduser -S -D -g "" -G nonroot -u 65532 nonroot
# additional cleanup
find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf
EOF
# expose dns_exporter default port
EXPOSE 15353
# copy dns_exporter
COPY --from=tmp --chown=nonroot:nonroot /home/nonroot /home/nonroot
# switch to nonroot user for runtime
USER nonroot
ENTRYPOINT [ "/home/nonroot/.local/bin/dns_exporter", "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
