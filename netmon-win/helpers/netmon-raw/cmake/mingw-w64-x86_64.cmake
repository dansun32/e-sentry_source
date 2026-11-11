# Cross-compile from Linux: cmake -S . -B build-mingw -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake
# Works with distro mingw-w64 (x86_64-w64-mingw32-g++) or llvm-mingw (set MINGW_PREFIX=/opt/llvm-mingw/bin/).
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(_p "$ENV{MINGW_PREFIX}")
set(CMAKE_C_COMPILER ${_p}x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER ${_p}x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER ${_p}x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
