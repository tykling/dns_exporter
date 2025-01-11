#syntax=docker/dockerfile:1
FROM python:3.12-alpine@sha256:54bec49592c8455de8d5983d984efff76b6417a6af9b5dcc8d0237bf6ad3bd20 AS builder
# install dependenciess for building package
RUN apk add -U -l -u gcc git libbsd-dev musl-dev openssl-dev
# install dns_exporter
RUN --mount=type=bind,readwrite,source=/,target=/src pip install --user /src
# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

FROM python:3.12-alpine@sha256:54bec49592c8455de8d5983d984efff76b6417a6af9b5dcc8d0237bf6ad3bd20 AS runtime
RUN \
--mount=type=bind,from=builder,source=/root/.local,target=/tmp/.local \
--mount=type=bind,source=/src/dns_exporter/dns_exporter_example.yml,target=/tmp/dns_exporter.yml \
<<EOF
# add nonroot group
addgroup -g 65532 -S nonroot
# add nonroot user
adduser -S -D -g "" -G nonroot -u 65532 nonroot
# copy files from mounts
cp -r /tmp/.local /tmp/dns_exporter.yml /home/nonroot/
# fix permissions
chown -R nonroot:nonroot /home/nonroot
# additional cleanup
find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf
EOF
# expose dns_exporter default port
EXPOSE 15353
# switch to nonroot user for runtime
USER nonroot
ENTRYPOINT [ "/home/nonroot/.local/bin/dns_exporter", "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
