cmake_minimum_required(VERSION 3.16)
project(Debugger)

set(CMAKE_CXX_STANDARD 20)

set(SOURCE_FILES main.cpp)
set(CMAKE_BUILD_TYPE Debug)

#find_package(Boost 1.69 OPTIONAL_COMPONENTS program_options thread date_time filesystem regex REQUIRED)
#include_directories(${Boost_INCLUDE_DIR})

add_executable(debugger ${SOURCE_FILES})
target_link_libraries(debugger capstone)
