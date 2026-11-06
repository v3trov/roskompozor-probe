#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
make -C src
# The include harness deliberately doesn't call daemon functions.
# pkg-config deliberately produces a list of compiler/linker arguments.
# shellcheck disable=SC2046
cc -std=c11 -O1 -g -Wall -Wextra -Wno-unused-function -Wno-misleading-indentation \
    tests/harness.c $(pkg-config --cflags --libs openssl json-c libcurl libidn) \
    -lpthread -lm -o tests/harness
cc -std=c11 -O1 -g -Wall -Wextra -Werror -shared -fPIC tests/netshim.c -ldl -o tests/netshim.so
python3 -m unittest discover -s tests -p 'test_native.py' -v
