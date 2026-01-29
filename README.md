# Session Storage Server

High-performance C++ storage server for the Lux Session network with GPU acceleration.

## Overview

This is the C++ implementation of the Session storage server, designed for high-throughput message storage and retrieval with post-quantum cryptographic security. It provides the backend infrastructure for the [SessionVM](https://github.com/luxfi/session) ecosystem.

## Features

- **High Performance**: Optimized C++ implementation with GPU acceleration
- **Post-Quantum Crypto**: ML-KEM-768 and ML-DSA-65 via [luxcpp/crypto](https://github.com/luxcpp/crypto)
- **GPU Acceleration**: Metal (Apple), CUDA (NVIDIA), WebGPU support
- **CGO Bindings**: Seamless integration with Go applications
- **Swarm Architecture**: Distributed storage across service nodes

## Building from Source

### Requirements

- CMake >= 3.16
- C++20 compatible compiler
- OpenSSL >= 1.1.1
- libsodium >= 1.0.17
- pkg-config
- libcurl
- jemalloc (recommended)

### Build

```bash
git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### With CGO Support

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_CGO_LIB=ON
cmake --build build --parallel
```

This produces `libsession_cgo.a` for Go integration.

### With GPU Acceleration

```bash
# Metal (macOS)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_METAL=ON
cmake --build build --parallel

# CUDA (Linux/Windows)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_CUDA=ON
cmake --build build --parallel
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   luxcpp/session                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   daemon/   │  │   server/   │  │    storage/     │  │
│  │   parsd     │  │  HTTPS/QUIC │  │    SQLite       │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   snode/    │  │    rpc/     │  │    crypto/      │  │
│  │   Swarm     │  │  Endpoints  │  │   PQ Adapter    │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                   luxcpp/crypto                          │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │  ML-KEM    │  │  ML-DSA    │  │    GPU Accel     │   │
│  │   768      │  │    65      │  │  Metal/CUDA      │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## CGO Integration

The storage server can be linked into Go applications:

```go
// #cgo LDFLAGS: -L${SRCDIR}/lib -lsession_cgo
// #include "session_cgo.h"
import "C"

func StoreMessage(sessionID string, data []byte) error {
    // Call C++ storage backend
}
```

## Directory Structure

```
session/
├── cmake/           # CMake modules
├── contrib/         # Scripts and utilities
├── external/        # External dependencies
├── include/         # Public headers (CGO)
├── pars/            # Pars-specific integration
│   ├── crypto/      # PQ crypto adapter
│   ├── daemon/      # parsd daemon
│   └── rpc/         # Lux RPC endpoints
├── session/
│   ├── common/      # Common types
│   ├── crypto/      # Channel encryption
│   ├── daemon/      # Storage daemon
│   ├── http/        # HTTP client
│   ├── logging/     # Logging
│   ├── rpc/         # RPC endpoints
│   ├── server/      # HTTPS/QUIC/OMQ servers
│   ├── snode/       # Service node logic
│   ├── storage/     # SQLite storage
│   └── utils/       # Utilities
├── src/             # CGO source
└── unit_test/       # Unit tests
```

## Related Repositories

- **[luxfi/session](https://github.com/luxfi/session)** - Go SessionVM implementation
- **[luxcpp/crypto](https://github.com/luxcpp/crypto)** - C++ cryptographic primitives
- **[luxcpp/gpu](https://github.com/luxcpp/gpu)** - GPU acceleration framework
- **[luxcpp/metal](https://github.com/luxcpp/metal)** - Metal shaders (Apple)
- **[luxcpp/cuda](https://github.com/luxcpp/cuda)** - CUDA kernels (NVIDIA)
- **[parsdao/node](https://github.com/parsdao/node)** - Pars blockchain node

## Testing

```bash
# Build and run unit tests
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure

# Network integration tests
cd network-tests
pytest -v
```

## Documentation

- [luxcpp.github.io](https://luxcpp.github.io) - C++ Libraries Documentation
- [LIP-7001](https://github.com/luxfi/lips/blob/main/LIPs/lip-7001-dao-governance-standard.md) - DAO Governance Standard

## License

Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
See [LICENSE](./LICENSE) for details.
