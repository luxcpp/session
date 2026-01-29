// session_cgo.cpp - C interface implementation for Go bindings
// SPDX-License-Identifier: MIT

#include "session_cgo.h"
#include "crypto/lux_crypto_adapter.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// For now, use stub implementations until full integration
// TODO: Link with actual storage server when built

namespace {

// Version info
constexpr const char* VERSION = "3.0.0";
constexpr const char* BUILD_INFO = "session-cgo built with ML-KEM-768 + ML-DSA-65";

// Thread-safe hex encoding
constexpr char hex_chars[] = "0123456789abcdef";

std::string to_hex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[data[i] >> 4]);
        result.push_back(hex_chars[data[i] & 0x0f]);
    }
    return result;
}

}  // namespace

// Context implementation
struct session_context {
    pars::crypto::LuxCryptoAdapter crypto_adapter;
    bool initialized = false;
    std::mutex mutex;

    // For session ID string generation (not thread-safe)
    char session_id_string_buffer[2 + SESSION_ID_SIZE * 2 + 1];  // "07" + hex + null

    // Storage server state (stub)
    bool storage_running = false;
};

extern "C" {

session_context_t* session_context_new(void) {
    return new (std::nothrow) session_context();
}

session_error_t session_init(session_context_t* ctx) {
    if (!ctx) return SESSION_ERR_INVALID_INPUT;

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (ctx->initialized) return SESSION_OK;

    auto err = ctx->crypto_adapter.init();
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    ctx->initialized = true;
    return SESSION_OK;
}

void session_shutdown(session_context_t* ctx) {
    if (!ctx) return;

    {
        std::lock_guard<std::mutex> lock(ctx->mutex);
        ctx->crypto_adapter.shutdown();
        ctx->initialized = false;
    }

    delete ctx;
}

int session_gpu_available(const session_context_t* ctx) {
    if (!ctx) return 0;
    return ctx->crypto_adapter.is_gpu_available() ? 1 : 0;
}

// ============================================================================
// Identity Management
// ============================================================================

session_error_t session_generate_identity(
    session_context_t* ctx,
    session_identity_t* identity
) {
    if (!ctx || !identity) return SESSION_ERR_INVALID_INPUT;

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::ParsIdentity pq_identity;
    auto err = ctx->crypto_adapter.generate_pars_identity(pq_identity);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    // Copy to C struct
    std::memcpy(identity->kem_public_key, pq_identity.kem_public_key.data(),
                SESSION_MLKEM768_PUBLIC_KEY_SIZE);
    std::memcpy(identity->kem_secret_key, pq_identity.kem_secret_key.data(),
                SESSION_MLKEM768_SECRET_KEY_SIZE);
    std::memcpy(identity->dsa_public_key, pq_identity.dsa_public_key.data(),
                SESSION_MLDSA65_PUBLIC_KEY_SIZE);
    std::memcpy(identity->dsa_secret_key, pq_identity.dsa_secret_key.data(),
                SESSION_MLDSA65_SECRET_KEY_SIZE);
    std::memcpy(identity->session_id, pq_identity.session_id.data(),
                SESSION_ID_SIZE);

    return SESSION_OK;
}

session_error_t session_derive_id(
    session_context_t* ctx,
    const uint8_t* kem_public_key,
    const uint8_t* dsa_public_key,
    uint8_t* session_id_out
) {
    if (!ctx || !kem_public_key || !dsa_public_key || !session_id_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLKEMPublicKey kem_pk;
    pars::crypto::MLDSAPublicKey dsa_pk;
    pars::crypto::SessionID sid;

    std::memcpy(kem_pk.data(), kem_public_key, SESSION_MLKEM768_PUBLIC_KEY_SIZE);
    std::memcpy(dsa_pk.data(), dsa_public_key, SESSION_MLDSA65_PUBLIC_KEY_SIZE);

    auto err = ctx->crypto_adapter.derive_session_id(kem_pk, dsa_pk, sid);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(session_id_out, sid.data(), SESSION_ID_SIZE);
    return SESSION_OK;
}

const char* session_derive_id_string(
    session_context_t* ctx,
    const uint8_t* kem_public_key,
    const uint8_t* dsa_public_key
) {
    if (!ctx || !kem_public_key || !dsa_public_key) {
        return nullptr;
    }

    uint8_t session_id[SESSION_ID_SIZE];
    if (session_derive_id(ctx, kem_public_key, dsa_public_key, session_id) != SESSION_OK) {
        return nullptr;
    }

    // Format: "07" + hex
    ctx->session_id_string_buffer[0] = '0';
    ctx->session_id_string_buffer[1] = '7';

    for (size_t i = 0; i < SESSION_ID_SIZE; ++i) {
        ctx->session_id_string_buffer[2 + i * 2] = hex_chars[session_id[i] >> 4];
        ctx->session_id_string_buffer[2 + i * 2 + 1] = hex_chars[session_id[i] & 0x0f];
    }
    ctx->session_id_string_buffer[2 + SESSION_ID_SIZE * 2] = '\0';

    return ctx->session_id_string_buffer;
}

// ============================================================================
// ML-KEM-768 Key Encapsulation
// ============================================================================

session_error_t session_mlkem768_keygen(
    session_context_t* ctx,
    uint8_t* public_key,
    uint8_t* secret_key
) {
    if (!ctx || !public_key || !secret_key) return SESSION_ERR_INVALID_INPUT;

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLKEMPublicKey pk;
    pars::crypto::MLKEMSecretKey sk;

    auto err = ctx->crypto_adapter.mlkem768_keygen(pk, sk);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(public_key, pk.data(), SESSION_MLKEM768_PUBLIC_KEY_SIZE);
    std::memcpy(secret_key, sk.data(), SESSION_MLKEM768_SECRET_KEY_SIZE);

    return SESSION_OK;
}

session_error_t session_mlkem768_encaps(
    session_context_t* ctx,
    const uint8_t* recipient_public_key,
    uint8_t* ciphertext_out,
    uint8_t* shared_secret_out
) {
    if (!ctx || !recipient_public_key || !ciphertext_out || !shared_secret_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLKEMPublicKey pk;
    pars::crypto::MLKEMCiphertext ct;
    pars::crypto::MLKEMSharedSecret ss;

    std::memcpy(pk.data(), recipient_public_key, SESSION_MLKEM768_PUBLIC_KEY_SIZE);

    auto err = ctx->crypto_adapter.mlkem768_encaps(pk, ct, ss);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(ciphertext_out, ct.data(), SESSION_MLKEM768_CIPHERTEXT_SIZE);
    std::memcpy(shared_secret_out, ss.data(), SESSION_MLKEM768_SHARED_SECRET_SIZE);

    return SESSION_OK;
}

session_error_t session_mlkem768_decaps(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret_out
) {
    if (!ctx || !secret_key || !ciphertext || !shared_secret_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLKEMSecretKey sk;
    pars::crypto::MLKEMCiphertext ct;
    pars::crypto::MLKEMSharedSecret ss;

    std::memcpy(sk.data(), secret_key, SESSION_MLKEM768_SECRET_KEY_SIZE);
    std::memcpy(ct.data(), ciphertext, SESSION_MLKEM768_CIPHERTEXT_SIZE);

    auto err = ctx->crypto_adapter.mlkem768_decaps(sk, ct, ss);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(shared_secret_out, ss.data(), SESSION_MLKEM768_SHARED_SECRET_SIZE);

    return SESSION_OK;
}

// ============================================================================
// ML-DSA-65 Digital Signatures
// ============================================================================

session_error_t session_mldsa65_keygen(
    session_context_t* ctx,
    uint8_t* public_key,
    uint8_t* secret_key
) {
    if (!ctx || !public_key || !secret_key) return SESSION_ERR_INVALID_INPUT;

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLDSAPublicKey pk;
    pars::crypto::MLDSASecretKey sk;

    auto err = ctx->crypto_adapter.mldsa65_keygen(pk, sk);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(public_key, pk.data(), SESSION_MLDSA65_PUBLIC_KEY_SIZE);
    std::memcpy(secret_key, sk.data(), SESSION_MLDSA65_SECRET_KEY_SIZE);

    return SESSION_OK;
}

session_error_t session_mldsa65_sign(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* message,
    size_t message_len,
    uint8_t* signature_out
) {
    if (!ctx || !secret_key || !message || message_len == 0 || !signature_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLDSASecretKey sk;
    pars::crypto::MLDSASignature sig;

    std::memcpy(sk.data(), secret_key, SESSION_MLDSA65_SECRET_KEY_SIZE);

    auto err = ctx->crypto_adapter.mldsa65_sign(
        sk,
        std::span<const uint8_t>(message, message_len),
        sig
    );
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    std::memcpy(signature_out, sig.data(), SESSION_MLDSA65_SIGNATURE_SIZE);

    return SESSION_OK;
}

session_error_t session_mldsa65_verify(
    session_context_t* ctx,
    const uint8_t* public_key,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature
) {
    if (!ctx || !public_key || !message || message_len == 0 || !signature) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    pars::crypto::MLDSAPublicKey pk;
    pars::crypto::MLDSASignature sig;

    std::memcpy(pk.data(), public_key, SESSION_MLDSA65_PUBLIC_KEY_SIZE);
    std::memcpy(sig.data(), signature, SESSION_MLDSA65_SIGNATURE_SIZE);

    auto err = ctx->crypto_adapter.mldsa65_verify(
        pk,
        std::span<const uint8_t>(message, message_len),
        sig
    );

    return static_cast<session_error_t>(err);
}

// ============================================================================
// Batch Verification
// ============================================================================

session_error_t session_batch_verify(
    session_context_t* ctx,
    const uint8_t** public_keys,
    const uint8_t** messages,
    const size_t* message_lens,
    const uint8_t** signatures,
    size_t count,
    int* results_out
) {
    if (!ctx || !public_keys || !messages || !message_lens ||
        !signatures || count == 0 || !results_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    std::lock_guard<std::mutex> lock(ctx->mutex);
    if (!ctx->initialized) return SESSION_ERR_NOT_INITIALIZED;

    // Convert to C++ types
    std::vector<pars::crypto::MLDSAPublicKey> pks(count);
    std::vector<std::vector<uint8_t>> msgs(count);
    std::vector<pars::crypto::MLDSASignature> sigs(count);
    std::vector<bool> results(count);

    for (size_t i = 0; i < count; ++i) {
        std::memcpy(pks[i].data(), public_keys[i], SESSION_MLDSA65_PUBLIC_KEY_SIZE);
        msgs[i].assign(messages[i], messages[i] + message_lens[i]);
        std::memcpy(sigs[i].data(), signatures[i], SESSION_MLDSA65_SIGNATURE_SIZE);
    }

    auto err = ctx->crypto_adapter.batch_verify(pks, msgs, sigs, results);
    if (err != pars::crypto::CryptoError::Success) {
        return static_cast<session_error_t>(err);
    }

    for (size_t i = 0; i < count; ++i) {
        results_out[i] = results[i] ? 0 : 1;
    }

    return SESSION_OK;
}

// ============================================================================
// Encryption
// ============================================================================

session_error_t session_encrypt_to_recipient(
    session_context_t* ctx,
    const uint8_t* recipient_public_key,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t** ciphertext_out,
    size_t* ciphertext_len_out
) {
    if (!ctx || !recipient_public_key || !plaintext || plaintext_len == 0 ||
        !ciphertext_out || !ciphertext_len_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    // TODO: Implement full encryption with XChaCha20-Poly1305
    // For now, return stub error
    return SESSION_ERR_NOT_INITIALIZED;
}

session_error_t session_decrypt_from_sender(
    session_context_t* ctx,
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t** plaintext_out,
    size_t* plaintext_len_out
) {
    if (!ctx || !secret_key || !ciphertext || ciphertext_len == 0 ||
        !plaintext_out || !plaintext_len_out) {
        return SESSION_ERR_INVALID_INPUT;
    }

    // TODO: Implement full decryption with XChaCha20-Poly1305
    return SESSION_ERR_NOT_INITIALIZED;
}

void session_free(void* ptr) {
    free(ptr);
}

// ============================================================================
// Storage Server Interface (stubs)
// ============================================================================

session_error_t session_storage_start(
    session_context_t* ctx,
    const session_storage_config_t* config
) {
    if (!ctx || !config) return SESSION_ERR_INVALID_INPUT;

    // TODO: Integrate with actual storage server
    ctx->storage_running = true;
    return SESSION_OK;
}

void session_storage_stop(session_context_t* ctx) {
    if (ctx) {
        ctx->storage_running = false;
    }
}

session_error_t session_storage_store(
    session_context_t* ctx,
    const uint8_t* recipient_id,
    const session_message_t* message
) {
    // TODO: Implement storage
    return SESSION_ERR_STORAGE_FAILED;
}

session_error_t session_storage_retrieve(
    session_context_t* ctx,
    const uint8_t* recipient_id,
    session_message_t** messages_out,
    size_t* count_out
) {
    // TODO: Implement retrieval
    return SESSION_ERR_STORAGE_FAILED;
}

void session_messages_free(session_message_t* messages, size_t count) {
    if (messages) {
        free(messages);
    }
}

// ============================================================================
// Version Information
// ============================================================================

const char* session_version(void) {
    return VERSION;
}

const char* session_build_info(void) {
    return BUILD_INFO;
}

}  // extern "C"
