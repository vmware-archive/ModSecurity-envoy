#!/bin/bash

# This script executes envoy's do_ci.sh
# However since the bazel target is //:envoy-static instead of //source/exe:envoy-static
# We use sed to rewrite those targets and execute the modified script

cd "$(dirname "$0")"/../envoy/ci

# Set $0 to match the envoy's do_ci.sh 
/bin/bash -c "eval `sed 's#source/exe##g' ./do_ci.sh`" "./do_ci.sh" $*
