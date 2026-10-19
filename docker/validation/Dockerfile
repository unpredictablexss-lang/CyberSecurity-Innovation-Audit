FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git python3 clang-14 libclang-common-14-dev && ln -sf /usr/bin/clang++-14 /usr/local/bin/clang++ && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/ohscanner
# Project code, harness, target source, and c_utils are mounted read-only at run time.
# The operation scratch directory is the only writable bind mount.
ENTRYPOINT ["python3"]
