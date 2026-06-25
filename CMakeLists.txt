cmake_minimum_required(VERSION 3.15)
project(AndroidLibredump)

set(CMAKE_CXX_STANDARD 17)

add_executable(dumper 
    main.cpp 
    dump.cpp 
    mem.cpp 
    extract.cpp
)

if(WIN32)
    target_link_options(dumper PRIVATE "-static")
    target_compile_definitions(dumper PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_link_libraries(dumper pthread)
endif()
