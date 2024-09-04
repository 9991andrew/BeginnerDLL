cmake_minimum_required(VERSION 3.7)
project(BeginnerDLL)

set(CMAKE_CXX_STANDARD 17)

# This tells CMake to build a shared library (DLL) rather than an executable
add_library(BeginnerDLL SHARED dllmain.cpp)