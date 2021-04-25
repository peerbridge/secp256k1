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

# Collect source files from https://github.com/bitcoin-core/secp256k1
file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS ext/secp256k1/include/*.h ext/secp256k1/src/*.h ext/secp256k1/src/secp256k1.c)

# Add source files and build a static library
add_library(secp256k1 STATIC library.cpp library.h bridge.cpp bridge.h encoding.cpp encoding.h ${SOURCE_FILES})

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

# Activate FetchContent module
include(FetchContent)

# Add GoogleTest - https://github.com/google/googletest
#FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/refs/tags/release-1.10.0.zip)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Download GoogleTest
FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()

# Add test executable and link googletest
add_executable(secp256k1_test library_test.cpp encoding_test.cpp)

# Link googletest against test executable
target_link_libraries(secp256k1_test gtest_main secp256k1)

# Enable GoogleTest module
include(GoogleTest)

# Discover Testcases
gtest_discover_tests(secp256k1_test)
