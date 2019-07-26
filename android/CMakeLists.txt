# Created by Keltika.
# Copyright (c) 2018 Excalibur (exc sp. z.o.o.). All rights reserved.
# NOTICE:  All information contained herein is, and remains
# the property of exc sp. z.o.o. and its suppliers,
# if any.  The intellectual and technical concepts contained
# herein are proprietary to exc sp. z.o.o.
# and its suppliers and may be covered by U.S. and Foreign Patents,
# patents in process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained
# from exc sp. z.o.o.

cmake_minimum_required(VERSION 3.4.1)

find_library( log-lib log )

# --------------------------------------------------------------------------------------------------
#   OPENSSL
#

# ssl library
add_library(
    openssl-lib
    STATIC
    IMPORTED
)

set_target_properties(
    openssl-lib
    PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/lib/${ANDROID_ABI}/libssl.a
)

# crypto library
add_library(
    openssl-crypto
    STATIC
    IMPORTED
)

set_target_properties(
    openssl-crypto
    PROPERTIES IMPORTED_LOCATION
    ${CMAKE_SOURCE_DIR}/lib/${ANDROID_ABI}/libcrypto.a
)

# --------------------------------------------------------------------------------------------------
#   EXCALIBUR CRYPTO
#
add_library(
    excalibur-crypto
    SHARED
    src/main/cpp/excalibur_crypto_jni.cpp
)

target_include_directories(
    excalibur-crypto
    PUBLIC
    include
)

target_compile_options(
    excalibur-crypto
    PUBLIC
    -std=c++11
)

target_link_libraries(
    excalibur-crypto
    openssl-lib
    openssl-crypto
    ${log-lib}
)