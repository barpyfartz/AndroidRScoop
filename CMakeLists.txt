cmake_minimum_required(VERSION 3.15)
project(AndroidLibredump) # old name K?

set(CMAKE_CXX_STANDARD 17)

if(WIN32)
    add_executable(dumper 
        main.cpp 
        dump.cpp 
        mem.cpp
    )
    target_compile_definitions(dumper PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(dumper PRIVATE DISABLE_APK_EXTRACT)
    target_link_options(dumper PRIVATE "-static")
else()
    find_package(ZLIB REQUIRED)
    add_executable(dumper 
        main.cpp 
        dump.cpp 
        mem.cpp 
        extract.cpp
    )
    target_link_libraries(dumper PRIVATE ZLIB::ZLIB pthread)
endif()
