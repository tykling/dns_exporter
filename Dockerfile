#syntax=docker/dockerfile:1.6.0
FROM python:3.12.2-alpine3.19 AS builder
# don't create .pyc files
ENV PYTHONDONTWRITEBYTECODE 1
# upgrade build image packages
RUN apk update
RUN apk upgrade -a -l
# install dependenciess for building package
RUN apk add --purge --clean-protected -l -u \
    alpine-sdk \
    cargo \
    libbsd-dev \
    libffi-dev \
    openssl-dev
# add nonroot user
RUN addgroup -g 65532 -S nonroot
RUN adduser -S -D -g "" -G nonroot -u 65532 nonroot
# switch to nonroot for package build
USER nonroot
# set workdir
WORKDIR /home/nonroot
# copy source
COPY --chown=nonroot:nonroot . .
# install dns_exporter
RUN pip install .
# cleanup
RUN find /home/nonroot/ | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf

FROM scratch AS tmp
# copy dns_exporter and dependencies
COPY --from=builder /home/nonroot/.local /home/nonroot/.local
# copy example config
COPY --from=builder /home/nonroot/src/dns_exporter/dns_exporter_example.yml /home/nonroot/dns_exporter.yml

FROM python:3.12.2-alpine3.19 AS runtime
# add nonroot user and do additional cleanup
RUN addgroup -g 65532 -S nonroot && \
    adduser -S -D -g "" -G nonroot -u 65532 nonroot && \
    # additional cleanup
    find / | grep -E "(\/.cache$|\/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf
# expose dns_exporter default port
EXPOSE 15353
# copy dns_exporter
COPY --from=tmp --chown=nonroot:nonroot /home/nonroot /home/nonroot
# switch to nonroot user for runtime
USER nonroot
CMD [ "/home/nonroot/.local/bin/dns_exporter", "-L", "0.0.0.0", "-c", "/home/nonroot/dns_exporter.yml" ]
