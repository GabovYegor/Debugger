cmake_minimum_required(VERSION 3.16)
project(Debugger)

set(CMAKE_CXX_STANDARD 20)

set(SOURCE_FILES main.cpp)

add_executable(debugger ${SOURCE_FILES})
target_link_libraries(debugger capstone)
