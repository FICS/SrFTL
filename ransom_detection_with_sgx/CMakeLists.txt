cmake_minimum_required(VERSION 2.8)
project(ransom_detection_in_sgx)

SET(CMAKE_C_COMPILER "g++")
set(CMAKE_CXX_STANDARD 11)

ADD_DEFINITIONS(-g -W -lpthread -Wall -std=c++11 -lrt -lm -lcrypto -lstdc++ -D_GNU_SOURCE -D_GLIBCXX_USE_CXX11_ABI=0 -fpermissive -O3)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

include_directories(./include)

message("${CMAKE_SOURCE_DIR}")

set(SOURCE_FILES include/detection.h src/detection.cpp detection_running.cpp )
add_executable(ransom_detection ${SOURCE_FILES})
