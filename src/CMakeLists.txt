cmake_minimum_required(VERSION 3.28)

find_package(MbedTLS REQUIRED)

add_executable(HTTPSClient
    client.c
)

target_link_libraries(HTTPSClient
    PUBLIC
        MbedTLS::mbedtls
        MbedTLS::mbedx509
        MbedTLS::mbedcrypto
    )