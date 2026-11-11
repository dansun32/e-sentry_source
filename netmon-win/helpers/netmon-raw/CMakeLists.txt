cmake_minimum_required(VERSION 3.16)
project(netmon_raw VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Portable logic (JSON, WFP summary, classification, args) - builds and tests on any OS.
add_library(netmon_raw_core STATIC src/core.cpp)
target_include_directories(netmon_raw_core PUBLIC src)

enable_testing()
add_executable(netmon-raw-tests tests/test_core.cpp)
target_link_libraries(netmon-raw-tests PRIVATE netmon_raw_core)
if(NOT CMAKE_CROSSCOMPILING)
  add_test(NAME core COMMAND netmon-raw-tests)
endif()

if(WIN32)
  add_executable(netmon-raw src/main.cpp src/capture.cpp src/wfp.cpp)
  target_link_libraries(netmon-raw PRIVATE netmon_raw_core fwpuclnt psapi advapi32 ole32 shell32 rpcrt4)
  target_compile_definitions(netmon-raw PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  if(MSVC)
    target_compile_options(netmon-raw PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(netmon_raw_core PRIVATE /W4 /permissive- /utf-8)
    # static CRT: no VC++ redistributable needed
    set_property(TARGET netmon-raw netmon_raw_core netmon-raw-tests PROPERTY
                 MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    target_compile_options(netmon-raw PRIVATE -Wall -Wextra)
    target_link_options(netmon-raw PRIVATE -static)
    target_link_options(netmon-raw-tests PRIVATE -static)
  endif()
endif()
