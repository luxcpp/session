// session_cgo.h - C interface for Go bindings
// SPDX-License-Identifier: MIT
//
// Pure C interface to Session crypto and storage server for CGO integration.
// This wraps the C++ LuxCryptoAdapter for use from Go.

#ifndef SESSION_CGO_H
#define SESSION_CGO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ML-KEM-768 constants (NIST Level 3)
#define SESSION_MLKEM768_PUBLIC_KEY_SIZE  1184
#define SESSION_MLKEM768_SECRET_KEY_SIZE  2400
#define SESSION_MLKEM768_CIPHERTEXT_SIZE  1088
#define SESSION_MLKEM768_SHARED_SECRET_SIZE 32

// ML-DSA-65 constants (NIST Level 3)
#define SESSION_MLDSA65_PUBLIC_KEY_SIZE   1952
#define SESSION_MLDSA65_SECRET_KEY_SIZE   4032
#define SESSION_MLDSA65_SIGNATURE_SIZE    3309

// Session ID size (Blake2b-256 output)
#define SESSION_ID_SIZE 32

// Error codes
typedef enum {
    SESSION_OK = 0,
    SESSION_ERR_INVALID_INPUT = -1,
    SESSION_ERR_KEYGEN_FAILED = -2,
    SESSION_ERR_ENCAPS_FAILED = -3,
    SESSION_ERR_DECAPS_FAILED = -4,
    SESSION_ERR_SIGN_FAILED = -5,
    SESSION_ERR_VERIFY_FAILED = -6,
    SESSION_ERR_GPU_INIT_FAILED = -7,
    SESSION_ERR_GPU_NOT_AVAILABLE = -8,
    SESSION_ERR_BATCH_VERIFY_FAILED = -9,
    SESSION_ERR_NOT_INITIALIZED = -10,
    SESSION_ERR_STORAGE_FAILED = -11,
    SESSION_ERR_NETWORK_FAILED = -12,
} session_error_t;

// Opaque context handle
typedef struct session_context session_context_t;

// Identity structure for Go
typedef struct {
    uint8_t kem_public_key[SESSION_MLKEM768_PUBLIC_KEY_SIZE];
    uint8_t kem_secret_key[SESSION_MLKEM768_SECRET_KEY_SIZE];
    uint8_t dsa_public_key[SESSION_MLDSA65_PUBLIC_KEY_SIZE];
    uint8_t dsa_secret_key[SESSION_MLDSA65_SECRET_KEY_SIZE];
    uint8_t session_id[SESSION_ID_SIZE];
} session_identity_t;

// Message structure
typedef struct {
    const uint8_t* data;
    size_t len;
    uint64_t timestamp;
    uint64_t ttl;
} session_message_t;

// ============================================================================
// Initialization
// ============================================================================

// Create a new session context (must call session_init before use)
session_context_t* session_context_new(void);

// Initialize the session context (GPU detection, crypto init)
session_error_t session_init(session_context_t* ctx);

// Shutdown and free resources
void session_shutdown(session_context_t* ctx);

// Check if GPU acceleration is available
int session_gpu_available(const session_context_t* ctx);

// ============================================================================
// Identity Management
// ============================================================================

// Generate a new post-quantum identity (ML-KEM-768 + ML-DSA-65)
session_error_t session_generate_identity(
    session_context_t* ctx,
    session_identity_t* identity
);

// Derive session ID from public keys: "07" prefix + Blake2b-256(kem_pk || dsa_pk)
session_error_t session_derive_id(
    session_context_t* ctx,
    const uint8_t* kem_public_key,
    const uint8_t* dsa_public_key,
    uint8_t* session_id_out
);

// Derive session ID as hex string (returns pointer to static buffer, not thread-safe)
// Format: "07" + hex(Blake2b-256(kem_pk || dsa_pk))
const char* session_derive_id_string(
    session_context_t* ctx,
    const uint8_t* kem_public_key,
    const uint8_t* dsa_public_key
);

// ============================================================================
// ML-KEM-768 Key Encapsulation
// ============================================================================

// Generate ML-KEM-768 keypair
session_error_t session_mlkem768_keygen(
    session_context_t* ctx,
    uint8_t* public_key,
    uint8_t* secret_key
);

// Encapsulate: create ciphertext and shared secret for recipient
session_error_t session_mlkem768_encaps(
    session_context_t* ctx,
    const uint8_t* recipient_public_key,
    uint8_t* ciphertext_out,
    uint8_t* shared_secret_out
);

// Decapsulate: recover shared secret from ciphertext
session_error_t session_mlkem768_decaps(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret_out
);

// ============================================================================
// ML-DSA-65 Digital Signatures
// ============================================================================

// Generate ML-DSA-65 keypair
session_error_t session_mldsa65_keygen(
    session_context_t* ctx,
    uint8_t* public_key,
    uint8_t* secret_key
);

// Sign a message
session_error_t session_mldsa65_sign(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out
);

// Verify a signature (returns SESSION_OK if valid)
session_error_t session_mldsa65_verify(
    session_context_t* ctx,
    const uint8_t* public_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature
);

// ============================================================================
// Batch Verification (GPU-accelerated when available)
// ============================================================================

// Verify multiple signatures in batch
// results_out must be pre-allocated array of count ints (0 = valid, non-zero = invalid)
session_error_t session_batch_verify(
    session_context_t* ctx,
    const uint8_t** public_keys,
    const uint8_t** messages,
    const size_t* message_lens,
    const uint8_t** signatures,
    size_t count,
    int* results_out
);

// ============================================================================
// Encryption (XChaCha20-Poly1305 with KEM)
// ============================================================================

// Encrypt message to recipient using their public key
// Returns allocated buffer (caller must free with session_free)
// Output format: KEM_ciphertext || XChaCha20-Poly1305(nonce || ciphertext || tag)
session_error_t session_encrypt_to_recipient(
    session_context_t* ctx,
    const uint8_t* recipient_public_key,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t** ciphertext_out,
    size_t* ciphertext_len_out
);

// Decrypt message using our secret key
// Returns allocated buffer (caller must free with session_free)
session_error_t session_decrypt_from_sender(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t** plaintext_out,
    size_t* plaintext_len_out
);

// Free memory allocated by session functions
void session_free(void* ptr);

// ============================================================================
// Storage Server Interface
// ============================================================================

// Storage server configuration
typedef struct {
    const char* data_dir;       // Directory for persistent storage
    const char* bind_address;   // Address to bind to (e.g., "0.0.0.0:22021")
    int num_workers;            // Number of worker threads (0 = auto)
    int enable_onion;           // Enable onion routing (1 = yes)
} session_storage_config_t;

// Start the storage server (blocks until shutdown)
session_error_t session_storage_start(
    session_context_t* ctx,
    const session_storage_config_t* config
);

// Signal storage server to stop
void session_storage_stop(session_context_t* ctx);

// Store a message
session_error_t session_storage_store(
    session_context_t* ctx,
    const uint8_t* recipient_id,
    const session_message_t* message
);

// Retrieve messages for a recipient
// Returns array of messages (caller must free with session_messages_free)
session_error_t session_storage_retrieve(
    session_context_t* ctx,
    const uint8_t* recipient_id,
    session_message_t** messages_out,
    size_t* count_out
);

// Free message array
void session_messages_free(session_message_t* messages, size_t count);

// ============================================================================
// Version Information
// ============================================================================

// Get library version string
const char* session_version(void);

// Get build info string
const char* session_build_info(void);

#ifdef __cplusplus
}
#endif

#endif // SESSION_CGO_H
