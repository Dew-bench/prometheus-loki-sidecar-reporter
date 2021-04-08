#!/bin/sh

# apk add perf
# apk add build-base
# apk add binutils
# apk add linux-headers
# apk add git

apk update
# python pypcap deps
apk add python3 py3-pip libpcap libpcap-dev python3-dev build-base
# python perf terminal cmd
apk add perf
