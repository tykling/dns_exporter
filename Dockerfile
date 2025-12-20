#syntax=docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
ARG TARGET_PLATFORM=linux/amd64
FROM --platform=$TARGET_PLATFORM python:3.14-alpine@sha256:7af51ebeb83610fb69d633d5c61a2efb87efa4caf66b59862d624bb6ef788345 AS builder
ENV \
PIP_DISABLE_PIP_VERSION_CHECK=1 \
PIP_NO_COMPILE=1 \
PIP_NO_WARN_SCRIPT_LOCATION=0 \
PIP_ROOT_USER_ACTION=ignore

# install dependenciess for building package
RUN apk add --update-cache --latest --upgrade --no-cache git
RUN pip install -U pip --no-cache-dir
RUN pip install -U build --no-cache-dir

# build & install dns_exporter package
RUN \
--mount=type=bind,readwrite,source=/,target=/src \
<<EOF
python -m build -o /src/build /src
pip install --user /src/build/dns_exporter-*.whl --no-cache-dir
EOF

# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

FROM --platform=$TARGET_PLATFORM python:3.14-alpine@sha256:7af51ebeb83610fb69d633d5c61a2efb87efa4caf66b59862d624bb6ef788345 AS runtime
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
