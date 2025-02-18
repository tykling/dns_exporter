#syntax=docker/dockerfile:1@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25
ARG TARGET_PLATFORM=linux/amd64
FROM --platform=$TARGET_PLATFORM python:3.13-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352 AS builder
# install dependenciess for building package
RUN apk add -U -l -u bsd-compat-headers cargo gcc git libffi-dev musl-dev openssl-dev
# install dns_exporter
RUN --mount=type=bind,readwrite,source=/,target=/src pip install --user /src
# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

FROM --platform=$TARGET_PLATFORM python:3.13-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352 AS runtime
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
