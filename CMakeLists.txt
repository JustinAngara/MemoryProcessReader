cmake_minimum_required(VERSION 3.10)
project(memory_reader)

set(CMAKE_C_STANDARD 99)

add_executable(memory_reader
        main.c
        read_memory.c
)

target_link_libraries(memory_reader psapi)
