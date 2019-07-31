#!/bin/bash
set -e

# Requirements by ModSecurity
apt-get update
export DEBIAN_FRONTEND=noninteractive
apt-get install -y libtool cmake realpath clang-format-5.0 automake
apt-get install -y g++ flex bison curl doxygen libyajl-dev libgeoip-dev libtool dh-autoreconf libcurl4-gnutls-dev libxml2 libpcre++-dev libxml2-dev