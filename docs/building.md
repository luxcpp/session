# Building

## Requirements

- CMake >= 3.16
- C++20 compatible compiler
- OpenSSL >= 1.1.1
- libsodium >= 1.0.17
- pkg-config
- libcurl
- jemalloc (recommended)

## Standard Build

```bash
git submodule update --init --recursive
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_CGO_LIB` | OFF | Build CGO library for Go |
| `BUILD_TESTS` | OFF | Build unit tests |
| `BUILD_STATIC_DEPS` | OFF | Build static dependencies |
| `ENABLE_METAL` | OFF | Enable Metal GPU acceleration |
| `ENABLE_CUDA` | OFF | Enable CUDA GPU acceleration |

## With CGO Support

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_CGO_LIB=ON
cmake --build build --parallel
```

Produces `libsession_cgo.a` for Go integration.

## With GPU Acceleration

### Metal (macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_METAL=ON
cmake --build build --parallel
```

### CUDA (Linux/Windows)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_CUDA=ON
cmake --build build --parallel
```

## Testing

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```
