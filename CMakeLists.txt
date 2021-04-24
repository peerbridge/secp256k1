# Sets the minimum version of CMake required to build the native library.
cmake_minimum_required(VERSION 3.19)

# Declare and name the project.
project(secp256k1 LANGUAGES C CXX)

# Set C++ Standard Version
set(CMAKE_CXX_STANDARD 17)

# Include https://github.com/bitcoin-core/secp256k1
# The included directory is set to the root instead of the
# typicall "secp256k1/include" directory with all header files
# since, secp256k1.c uses include paths like "include/secp256k1.h"
include_directories(ext/secp256k1 ext/secp256k1/src)

# Add source files and build a static library
add_library(secp256k1 STATIC library.cpp library.h bridge.cpp bridge.h)

# Specify compile definitions used to build the library # USE_ECMULT_STATIC_PRECOMPUTATION
target_compile_definitions(
        secp256k1

        PUBLIC
            ENABLE_MODULE_ECDH
            ENABLE_MODULE_RECOVERY
            ENABLE_MODULE_EXTRAKEYS
            ENABLE_MODULE_SCHNORRSIG

            USE_NUM_NONE
            USE_ENDOMORPHISM
            USE_FIELD_INV_BUILTIN
            USE_SCALAR_INV_BUILTIN

            ECMULT_WINDOW_SIZE=15
            ECMULT_GEN_PREC_BITS=4
)
