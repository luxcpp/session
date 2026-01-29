# CGO Integration

The storage server provides CGO bindings for Go applications.

## Building the CGO Library

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_CGO_LIB=ON
cmake --build build --parallel
```

This produces `libsession_cgo.a`.

## Header

```c
// session_cgo.h
#ifndef SESSION_CGO_H
#define SESSION_CGO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize storage backend
int session_init(const char* db_path);

// Store message
int session_store(
    const char* session_id,
    const uint8_t* data,
    size_t data_len
);

// Retrieve message
int session_retrieve(
    const char* session_id,
    uint8_t** data,
    size_t* data_len
);

// Cleanup
void session_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // SESSION_CGO_H
```

## Go Usage

```go
package storage

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lsession_cgo -lstdc++
#include "session_cgo.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

func Init(dbPath string) error {
    cPath := C.CString(dbPath)
    defer C.free(unsafe.Pointer(cPath))

    if C.session_init(cPath) != 0 {
        return errors.New("failed to initialize storage")
    }
    return nil
}

func Store(sessionID string, data []byte) error {
    cID := C.CString(sessionID)
    defer C.free(unsafe.Pointer(cID))

    if C.session_store(cID, (*C.uint8_t)(&data[0]), C.size_t(len(data))) != 0 {
        return errors.New("failed to store message")
    }
    return nil
}
```
