cmake_minimum_required(VERSION 3.16)

project(SecureProxy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(include)

add_executable(proxy
    src/proxy.cpp
    src/tls_server.cpp
    src/session_manager.cpp
    src/redis_client.cpp
    src/ebpf_manager.cpp
    src/dispatcher.cpp
)

target_link_libraries(proxy
    OpenSSL::SSL
    OpenSSL::Crypto
    hiredis
    bpf
    Threads::Threads
)

target_include_directories(proxy PRIVATE
    include
    ebpf
)
