# Minimal image able to compile and run the component harness.
# Matches the compiler recorded in results/component/logs/compile.log:
#   Ubuntu clang version 14.0.0-1ubuntu1.1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang \
 && rm -rf /var/lib/apt/lists/*
