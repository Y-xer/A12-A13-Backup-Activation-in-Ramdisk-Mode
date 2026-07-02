# MILODEV

A high-performance, industry-grade C++ automation suite engineered by **MiloDev**. This engine is specifically architected to handle complex multi-stage filesystem interactions, advanced block storage diagnostics, and secure cryptographic pipeline extractions via highly optimized SSH/SFTP environments.

## Features
- **Dynamic Partition Enumeration:** Real-time discovery and sorting of block storage nodes (`/dev/disk*`).
- **Adaptive Mount Matrix:** Multi-option APFS volume mounting sequence with automated fallback configurations (`-o rw`, `-o nomntsnap`, `-w`).
- **Strict I/O Validation:** Multi-layered write/read verification subsystem leveraging raw `dd` byte-stream mapping and append verification.
- **VFS Overlay Filtering:** Active hardware-level verification through `stat` differential telemetry to filter out virtual filesystem layers (`tmpfs`, `overlay`, `unionfs`).
- **Cryptographic Guard:** Localized post-extraction structural integrity checks and data hash validation via OpenSSL SHA-256.

## Developer
- **Dev:** MiloDev (Daoudi Yasser Abderahmane)

## Dependencies
Ensure the following development packages are installed on your host system before compiling:
- `libssh` (Development headers & binaries)
- `OpenSSL` (Crypto components)
- `CMake` (v3.10 or higher)
- `Make` or any native build toolchain
- A modern C++ compiler supporting the **C++17** standard (`gcc`, `clang`, or `MSVC`)

## Compilation & Building

To generate a precise production-ready build, execute the following precise sequence from your terminal root:

```bash
# 1. Instantiate an isolated compilation directory
mkdir -p build && cd build

# 2. Configure project and generate build systems via CMake
cmake -DCMAKE_BUILD_TYPE=Release ..

# 3. Compile the executable binary using optimal hardware threads
make -j$(nproc 2>/dev/null || echo 4)
