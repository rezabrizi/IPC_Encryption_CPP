cmake_minimum_required(VERSION 3.26)
project(IPC_Encryption)

set(CMAKE_CXX_STANDARD 17)

add_executable(IPC_Encryption main.cpp
        encryption.cpp
        logger.cpp)
