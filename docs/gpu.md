# GPU Acceleration

The storage server supports GPU acceleration for cryptographic operations.

## Supported Backends

| Backend | Platform | Library |
|---------|----------|---------|
| Metal | macOS, iOS | [luxcpp/metal](https://github.com/luxcpp/metal) |
| CUDA | Linux, Windows | [luxcpp/cuda](https://github.com/luxcpp/cuda) |
| WebGPU | Cross-platform | [luxcpp/webgpu](https://github.com/luxcpp/webgpu) |

## Metal (Apple Silicon)

Optimized for Apple M-series chips:

```bash
cmake -B build -DENABLE_METAL=ON
cmake --build build
```

Uses Metal Performance Shaders for:
- Matrix operations in ML-KEM
- Parallel signature verification

## CUDA (NVIDIA)

For NVIDIA GPUs:

```bash
cmake -B build -DENABLE_CUDA=ON -DCUDA_TOOLKIT_ROOT_DIR=/usr/local/cuda
cmake --build build
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   luxcpp/session                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Crypto Operations                   │    │
│  └─────────────────────┬───────────────────────────┘    │
└────────────────────────┼────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
    ┌─────────┐    ┌─────────┐    ┌─────────┐
    │  Metal  │    │  CUDA   │    │ WebGPU  │
    └─────────┘    └─────────┘    └─────────┘
```
