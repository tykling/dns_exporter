#syntax=docker/dockerfile:1.6.0
FROM python:3.12.2-alpine3.19 AS builder
# install dependenciess for building package
RUN apk add -U --purge --clean-protected -l -u --no-cache \
    alpine-sdk \
    cargo \
    libbsd-dev \
    libffi-dev \
    openssl-dev
# add nonroot group
RUN addgroup -g 65532 -S nonroot
# add nonroot user
RUN adduser -S -D -g "" -G nonroot -u 65532 nonroot
# switch to nonroot for package build
USER nonroot
# set workdir
WORKDIR /home/nonroot
# copy source
COPY --chown=nonroot:nonroot . .
# install dns_exporter
RUN pip install .
# switch back to root for initial cleanup
USER root
# cleanup
RUN find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

# create tmp container for copying files
FROM scratch AS tmp
# copy dns_exporter and dependencies
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
# copy example config
COPY --from=builder /home/nonroot/src/dns_exporter/dns_exporter_example.yml /home/nonroot/dns_exporter.yml

FROM python:3.12.2-alpine3.19 AS runtime
# add nonroot group
RUN addgroup -g 65532 -S nonroot && \
    # add nonroot user
    adduser -S -D -g "" -G nonroot -u 65532 nonroot && \
    # additional cleanup
    find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf
# expose dns_exporter default port
EXPOSE 15353
# copy dns_exporter
COPY --from=tmp --chown=nonroot:nonroot /home/nonroot /home/nonroot
# switch to nonroot user for runtime
USER nonroot
ENTRYPOINT [ "/home/nonroot/.local/bin/dns_exporter", "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
