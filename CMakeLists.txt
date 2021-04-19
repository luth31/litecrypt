cmake_minimum_required(VERSION 3.10)

# Disable generation in source directory
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(litecrypt VERSION 0.0.1 DESCRIPTION "An amateur cryptographic library" LANGUAGES C)

# Set default build type to Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

# Collect all source files into $SOURCES
file(GLOB SOURCES
    ${CMAKE_SOURCE_DIR}/src/*.c)

# Create object from collected sources and include headers
add_library(objlib OBJECT ${SOURCES})
target_include_directories(objlib PUBLIC include)
target_include_directories(objlib PRIVATE src)

# Enable PIC for correct function of shared library
set_property(TARGET objlib PROPERTY POSITION_INDEPENDENT_CODE 1)

# Create shared and static library from 
add_library(litecrypt_shared SHARED $<TARGET_OBJECTS:objlib>)
add_library(litecrypt_static STATIC $<TARGET_OBJECTS:objlib>)

# Add test executable
add_executable(litecrypt_test ${CMAKE_SOURCE_DIR}/tests/main.c $<TARGET_OBJECTS:objlib>)
target_include_directories(litecrypt_test PUBLIC include)

# Set library version
set_target_properties(litecrypt_shared PROPERTIES 
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})