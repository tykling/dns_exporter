#syntax=docker/dockerfile:1
FROM python:3.13-alpine@sha256:be540041682c83228415ca1dbdb061d78d6994523e8ff79c5d5b2a5cab56effb AS builder
# install dependenciess for building package
RUN apk add -U -l -u bsd-compat-headers gcc git musl-dev openssl-dev
# install dns_exporter
RUN --mount=type=bind,readwrite,source=/,target=/src pip install --user /src
# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

FROM python:3.13-alpine@sha256:be540041682c83228415ca1dbdb061d78d6994523e8ff79c5d5b2a5cab56effb AS runtime
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
ENTRYPOINT [ "/home/nonroot/.local/bin/dns_exporter" ]
CMD [ "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
