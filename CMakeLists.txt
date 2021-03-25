cmake_minimum_required(VERSION 3.10)

project(litecrypt VERSION 0.0.1 DESCRIPTION "An amateur cryptographic library" LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
endif()

file(GLOB SOURCES
    ${CMAKE_SOURCE_DIR}/src/*.c)

add_library(litecrypt SHARED ${SOURCES})

set_target_properties(litecrypt PROPERTIES 
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})