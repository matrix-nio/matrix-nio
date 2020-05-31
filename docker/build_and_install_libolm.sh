#!/usr/bin/env sh
#
# Call with the following arguments:
#
#    ./build_and_install_libolm.sh <libolm version> <python bindings install dir>
#
# Example:
#
#    ./build_and_install_libolm.sh 3.1.4 /python-bindings
#
# Note that if a python bindings installation directory is not supplied, bindings will
# be installed to the default directory.
#

set -ex

# Download the specified version of libolm
git clone -b "$1" https://gitlab.matrix.org/matrix-org/olm.git olm && cd olm

# Build libolm
cmake . -Bbuild
cmake --build build

# Install
make install

# Build the python3 bindings
cd python && make olm-python3

# Install python3 bindings
mkdir -p "$2"
DESTDIR="$2" make install-python3
