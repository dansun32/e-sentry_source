#!/usr/bin/env bash
# Cross-build the Windows helpers on Linux (how the prebuilt helpers/*.exe in this zip were made).
#   needs: .NET 8 SDK (dotnet-install.sh --channel 8.0), cmake + ninja, and a mingw-w64 C++ toolchain
#          (distro mingw-w64 or llvm-mingw; set MINGW_PREFIX=/opt/llvm-mingw/bin/ for the latter).
# The PyInstaller netmon-win.exe can only be built on Windows (see build.ps1 / CI).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p helpers build
dotnet test helpers/netmon-etw/tests/NetmonEtw.Tests
dotnet publish helpers/netmon-etw/src/NetmonEtw/NetmonEtw.csproj -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:DebugType=none -o build/etw
cp build/etw/netmon-etw.exe helpers/
cmake -S helpers/netmon-raw -B build/raw-mingw -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake
cmake --build build/raw-mingw
cp build/raw-mingw/netmon-raw.exe helpers/
# portable C++ unit tests with the host compiler
cmake -S helpers/netmon-raw -B build/raw-native -G Ninja && cmake --build build/raw-native && ctest --test-dir build/raw-native --output-on-failure
${PYTHON:-python3} -m pytest -q -p no:cacheprovider tests
