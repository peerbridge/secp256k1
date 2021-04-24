#!/usr/bin/env sh

set -e

# Get source directory of shell script
dir=$(CDPATH= cd -- "$(dirname -- "$0")/ext/secp256k1" && pwd)

# Navigate into shell script directory
cd "$dir" || exit 1

# Set C compiler, fallback to gcc
CC=${CC:-gcc}

# Compile src/gen_context.c
"$CC" "$dir/src/gen_context.c" -o "$dir/gen_context" -I"${dir}" -DECMULT_GEN_PREC_BITS=4

# Invoke binary to create "ecmult_static_context.h"
"$dir/gen_context"
