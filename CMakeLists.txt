cmake_minimum_required(VERSION 3.20)
project(netstack_starter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(netstack
    src/main.cpp
    src/net.cpp
)

target_include_directories(netstack PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic)
