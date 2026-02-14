cmake_minimum_required(VERSION 3.20)
project(crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# libraries
add_subdirectory(src/lib)

# tests
add_subdirectory(src/tests)