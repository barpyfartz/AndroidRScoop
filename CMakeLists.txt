cmake_minimum_required(VERSION 3.10)
project(roblox_dumper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(ZLIB REQUIRED)

add_executable(dumper
    main.cpp
    mem.cpp
    extract.cpp
    dump.cpp
)

target_link_libraries(dumper ZLIB::ZLIB)
