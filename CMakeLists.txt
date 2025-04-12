cmake_minimum_required(VERSION 3.26)
project(ollama-scanner)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)

set(CPM_SOURCE_CACHE ${CMAKE_BINARY_DIR}/cpm_cache CACHE PATH "CPM source cache directory")
if(DEFINED CPM_SOURCE_CACHE)
    message(STATUS "Using CPM Source Cache at: ${CPM_SOURCE_CACHE}")
else()
    message(WARNING "CPM_SOURCE_CACHE is not set! CPM will use default behavior.")
endif()

include(cmake/cpm.cmake)

CPMAddPackage(
        NAME cpr
        GITHUB_REPOSITORY libcpr/cpr
        GIT_TAG 1.9.8
        OPTIONS
        "BUILD_SHARED_LIBS OFF"
        "CPR_FORCE_USE_SYSTEM_CURL OFF"
        "CPR_BUILD_TESTS OFF"
        "CPR_ENABLE_SSL ON"
)

CPMAddPackage("gh:fmtlib/fmt#11.0.0")

add_executable(ollama-scanner src/main.cpp)

target_link_libraries(ollama-scanner PRIVATE
        cpr::cpr
        fmt::fmt
)