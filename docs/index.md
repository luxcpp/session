# Session Storage Server

High-performance C++ storage server for the Lux Session network.

## Overview

This is the C++ implementation of the Session storage server, designed for high-throughput message storage and retrieval with post-quantum cryptographic security.

## Quick Start

```bash
# Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# Run
./build/session-storage --help
```

## Contents

- [Building](./building.md) - Build instructions and options
- [GPU Acceleration](./gpu.md) - Metal, CUDA, WebGPU support
- [CGO Integration](./cgo.md) - Go bindings

## Related

- [luxfi/session](https://github.com/luxfi/session) - Go SessionVM implementation
- [luxcpp/crypto](https://github.com/luxcpp/crypto) - C++ cryptographic primitives
- [luxcpp/gpu](https://github.com/luxcpp/gpu) - GPU acceleration framework
