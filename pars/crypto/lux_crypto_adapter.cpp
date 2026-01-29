// lux_crypto_adapter.cpp - Implementation of lux crypto adapter
// SPDX-License-Identifier: MIT
//
// Provides GPU-accelerated ML-KEM-768 and ML-DSA-65 operations via Metal
// with automatic CPU fallback when GPU is unavailable.

#include "lux_crypto_adapter.h"

#include <cstring>
#include <iomanip>
#include <mutex>
#include <sstream>

// Logging support
#ifdef PARS_LOGGING
#include <pars/logging/pars_logger.h>
static auto logcat = pars::log::Cat("lux_crypto");
#define LOG_INFO(...)    pars::log::info(logcat, __VA_ARGS__)
#define LOG_WARNING(...) pars::log::warning(logcat, __VA_ARGS__)
#define LOG_ERROR(...)   pars::log::error(logcat, __VA_ARGS__)
#define LOG_DEBUG(...)   pars::log::debug(logcat, __VA_ARGS__)
#else
#include <cstdio>
#define LOG_INFO(fmt, ...)    std::fprintf(stderr, "[INFO] lux_crypto: " fmt "\n", ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) std::fprintf(stderr, "[WARN] lux_crypto: " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   std::fprintf(stderr, "[ERROR] lux_crypto: " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)   (void)0
#endif

namespace pars::crypto {

namespace {

// Global GPU context for lazy initialization
struct GlobalGPUContext {
    std::mutex mutex;
    MetalMLDSAContext* mldsa_ctx = nullptr;
    MetalMLKEMContext* mlkem_ctx = nullptr;
    bool initialized = false;
    bool gpu_available = false;
    int init_count = 0;  // Reference count
};

GlobalGPUContext& get_global_context() {
    static GlobalGPUContext ctx;
    return ctx;
}

// Convert bytes to hex string
std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

// Secure memory zeroing (prevent compiler optimization)
void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// LuxCryptoAdapter implementation
// ---------------------------------------------------------------------------

LuxCryptoAdapter::~LuxCryptoAdapter() {
    shutdown();
}

LuxCryptoAdapter::LuxCryptoAdapter(LuxCryptoAdapter&& other) noexcept
    : mldsa_ctx_(other.mldsa_ctx_)
    , mlkem_ctx_(other.mlkem_ctx_)
    , initialized_(other.initialized_)
    , gpu_available_(other.gpu_available_) {
    other.mldsa_ctx_ = nullptr;
    other.mlkem_ctx_ = nullptr;
    other.initialized_ = false;
    other.gpu_available_ = false;
}

LuxCryptoAdapter& LuxCryptoAdapter::operator=(LuxCryptoAdapter&& other) noexcept {
    if (this != &other) {
        shutdown();
        mldsa_ctx_ = other.mldsa_ctx_;
        mlkem_ctx_ = other.mlkem_ctx_;
        initialized_ = other.initialized_;
        gpu_available_ = other.gpu_available_;
        other.mldsa_ctx_ = nullptr;
        other.mlkem_ctx_ = nullptr;
        other.initialized_ = false;
        other.gpu_available_ = false;
    }
    return *this;
}

CryptoError LuxCryptoAdapter::init() {
    if (initialized_) {
        LOG_DEBUG("LuxCryptoAdapter already initialized");
        return CryptoError::Success;
    }

    LOG_INFO("Initializing Lux crypto adapter...");

    // Initialize the base lux crypto library
    int rc = lux_crypto_init();
    if (rc != 0) {
        LOG_ERROR("Failed to initialize lux crypto library: error code %d", rc);
        return CryptoError::GpuInitFailed;
    }

    // Check if Metal GPU acceleration is available
    if (metal_mldsa_available()) {
        LOG_INFO("Metal GPU acceleration available, creating contexts...");

        // Create Metal contexts for ML-KEM and ML-DSA
        mlkem_ctx_ = metal_mlkem_context_create();
        if (!mlkem_ctx_) {
            LOG_WARNING("Failed to create Metal ML-KEM context, falling back to CPU");
        }

        mldsa_ctx_ = metal_mldsa_context_create();
        if (!mldsa_ctx_) {
            LOG_WARNING("Failed to create Metal ML-DSA context, falling back to CPU");
            // Clean up ML-KEM context if ML-DSA failed
            if (mlkem_ctx_) {
                metal_mlkem_context_destroy(mlkem_ctx_);
                mlkem_ctx_ = nullptr;
            }
        }

        gpu_available_ = (mlkem_ctx_ != nullptr) && (mldsa_ctx_ != nullptr);

        if (gpu_available_) {
            LOG_INFO("GPU acceleration enabled for ML-KEM-768 and ML-DSA-65");
        } else {
            LOG_WARNING("GPU contexts not fully available, using CPU fallback");
        }
    } else {
        LOG_INFO("Metal GPU acceleration not available, using CPU implementation");
        gpu_available_ = false;
    }

    initialized_ = true;
    LOG_INFO("Lux crypto adapter initialized successfully (GPU: %s)",
             gpu_available_ ? "enabled" : "disabled");

    return CryptoError::Success;
}

void LuxCryptoAdapter::shutdown() {
    if (!initialized_) {
        return;
    }

    LOG_INFO("Shutting down Lux crypto adapter...");

    // Destroy Metal contexts
    if (mldsa_ctx_) {
        metal_mldsa_context_destroy(mldsa_ctx_);
        mldsa_ctx_ = nullptr;
    }

    if (mlkem_ctx_) {
        metal_mlkem_context_destroy(mlkem_ctx_);
        mlkem_ctx_ = nullptr;
    }

    // Shutdown base crypto library
    lux_crypto_shutdown();

    initialized_ = false;
    gpu_available_ = false;

    LOG_INFO("Lux crypto adapter shutdown complete");
}

bool LuxCryptoAdapter::is_gpu_available() const noexcept {
    return gpu_available_;
}

// ---------------------------------------------------------------------------
// ML-KEM-768 operations
// ---------------------------------------------------------------------------

CryptoError LuxCryptoAdapter::mlkem768_keygen(
    MLKEMPublicKey& public_key,
    MLKEMSecretKey& secret_key) {

    if (!initialized_) {
        LOG_ERROR("mlkem768_keygen: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mlkem768_keygen: using GPU acceleration");
        result = metal_mlkem_keygen(
            mlkem_ctx_,
            public_key.data(),
            secret_key.data()
        );
    } else {
        LOG_DEBUG("mlkem768_keygen: using CPU fallback");
        result = lux_crypto_mlkem768_keygen(
            public_key.data(),
            secret_key.data()
        );
    }

    if (result != 0) {
        LOG_ERROR("mlkem768_keygen failed: error code %d", result);
        return CryptoError::KeygenFailed;
    }

    LOG_DEBUG("mlkem768_keygen: success, pk prefix: %s...",
              to_hex(public_key.data(), 8).c_str());

    return CryptoError::Success;
}

CryptoError LuxCryptoAdapter::mlkem768_encaps(
    const MLKEMPublicKey& public_key,
    MLKEMCiphertext& ciphertext,
    MLKEMSharedSecret& shared_secret) {

    if (!initialized_) {
        LOG_ERROR("mlkem768_encaps: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mlkem768_encaps: using GPU acceleration");
        result = metal_mlkem_encaps(
            mlkem_ctx_,
            public_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    } else {
        LOG_DEBUG("mlkem768_encaps: using CPU fallback");
        result = lux_crypto_mlkem768_encaps(
            public_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    }

    if (result != 0) {
        LOG_ERROR("mlkem768_encaps failed: error code %d", result);
        return CryptoError::EncapsFailed;
    }

    LOG_DEBUG("mlkem768_encaps: success");
    return CryptoError::Success;
}

CryptoError LuxCryptoAdapter::mlkem768_decaps(
    const MLKEMSecretKey& secret_key,
    const MLKEMCiphertext& ciphertext,
    MLKEMSharedSecret& shared_secret) {

    if (!initialized_) {
        LOG_ERROR("mlkem768_decaps: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mlkem768_decaps: using GPU acceleration");
        result = metal_mlkem_decaps(
            mlkem_ctx_,
            secret_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    } else {
        LOG_DEBUG("mlkem768_decaps: using CPU fallback");
        result = lux_crypto_mlkem768_decaps(
            secret_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    }

    if (result != 0) {
        LOG_ERROR("mlkem768_decaps failed: error code %d", result);
        return CryptoError::DecapsFailed;
    }

    LOG_DEBUG("mlkem768_decaps: success");
    return CryptoError::Success;
}

// ---------------------------------------------------------------------------
// ML-DSA-65 operations
// ---------------------------------------------------------------------------

CryptoError LuxCryptoAdapter::mldsa65_keygen(
    MLDSAPublicKey& public_key,
    MLDSASecretKey& secret_key) {

    if (!initialized_) {
        LOG_ERROR("mldsa65_keygen: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mldsa65_keygen: using GPU acceleration");
        result = metal_mldsa_keygen(
            mldsa_ctx_,
            public_key.data(),
            secret_key.data()
        );
    } else {
        LOG_DEBUG("mldsa65_keygen: using CPU fallback");
        result = lux_crypto_mldsa65_keygen(
            public_key.data(),
            secret_key.data()
        );
    }

    if (result != 0) {
        LOG_ERROR("mldsa65_keygen failed: error code %d", result);
        return CryptoError::KeygenFailed;
    }

    LOG_DEBUG("mldsa65_keygen: success, pk prefix: %s...",
              to_hex(public_key.data(), 8).c_str());

    return CryptoError::Success;
}

CryptoError LuxCryptoAdapter::mldsa65_sign(
    const MLDSASecretKey& secret_key,
    std::span<const uint8_t> message,
    MLDSASignature& signature) {

    if (!initialized_) {
        LOG_ERROR("mldsa65_sign: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    if (message.empty()) {
        LOG_ERROR("mldsa65_sign: empty message");
        return CryptoError::InvalidInput;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mldsa65_sign: using GPU acceleration for %zu byte message",
                  message.size());
        result = metal_mldsa_sign(
            mldsa_ctx_,
            secret_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    } else {
        LOG_DEBUG("mldsa65_sign: using CPU fallback for %zu byte message",
                  message.size());
        result = lux_crypto_mldsa65_sign(
            secret_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    }

    if (result != 0) {
        LOG_ERROR("mldsa65_sign failed: error code %d", result);
        return CryptoError::SignFailed;
    }

    LOG_DEBUG("mldsa65_sign: success");
    return CryptoError::Success;
}

CryptoError LuxCryptoAdapter::mldsa65_verify(
    const MLDSAPublicKey& public_key,
    std::span<const uint8_t> message,
    const MLDSASignature& signature) {

    if (!initialized_) {
        LOG_ERROR("mldsa65_verify: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    if (message.empty()) {
        LOG_ERROR("mldsa65_verify: empty message");
        return CryptoError::InvalidInput;
    }

    int result;

    if (gpu_available_) {
        LOG_DEBUG("mldsa65_verify: using GPU acceleration");
        result = metal_mldsa_verify(
            mldsa_ctx_,
            public_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    } else {
        LOG_DEBUG("mldsa65_verify: using CPU fallback");
        result = lux_crypto_mldsa65_verify(
            public_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    }

    if (result != 0) {
        LOG_DEBUG("mldsa65_verify: signature invalid");
        return CryptoError::VerifyFailed;
    }

    LOG_DEBUG("mldsa65_verify: signature valid");
    return CryptoError::Success;
}

// ---------------------------------------------------------------------------
// Batch verification (GPU-accelerated)
// ---------------------------------------------------------------------------

CryptoError LuxCryptoAdapter::batch_verify(
    const std::vector<MLDSAPublicKey>& public_keys,
    const std::vector<std::vector<uint8_t>>& messages,
    const std::vector<MLDSASignature>& signatures,
    std::vector<bool>& results) {

    if (!initialized_) {
        LOG_ERROR("batch_verify: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    const size_t count = public_keys.size();

    if (count == 0) {
        LOG_ERROR("batch_verify: empty batch");
        return CryptoError::InvalidInput;
    }

    if (messages.size() != count || signatures.size() != count) {
        LOG_ERROR("batch_verify: mismatched array sizes (pks=%zu, msgs=%zu, sigs=%zu)",
                  count, messages.size(), signatures.size());
        return CryptoError::InvalidInput;
    }

    results.resize(count);

    // GPU batch verification path (only if GPU available and batch > 1)
    if (gpu_available_ && count > 1) {
        LOG_INFO("batch_verify: using GPU acceleration for %zu signatures", count);

        // Prepare batch data for GPU
        std::vector<const uint8_t*> pk_ptrs(count);
        std::vector<const uint8_t*> msg_ptrs(count);
        std::vector<size_t> msg_lens(count);
        std::vector<const uint8_t*> sig_ptrs(count);
        std::vector<int> batch_results(count);

        for (size_t i = 0; i < count; ++i) {
            pk_ptrs[i] = public_keys[i].data();
            msg_ptrs[i] = messages[i].data();
            msg_lens[i] = messages[i].size();
            sig_ptrs[i] = signatures[i].data();
        }

        int result = metal_mldsa_batch_verify(
            mldsa_ctx_,
            pk_ptrs.data(),
            msg_ptrs.data(),
            msg_lens.data(),
            sig_ptrs.data(),
            count,
            batch_results.data()
        );

        if (result != 0) {
            LOG_ERROR("batch_verify: GPU batch verification failed: %d", result);
            return CryptoError::BatchVerifyFailed;
        }

        size_t valid_count = 0;
        for (size_t i = 0; i < count; ++i) {
            results[i] = (batch_results[i] == 0);
            if (results[i]) ++valid_count;
        }

        LOG_INFO("batch_verify: %zu/%zu signatures valid", valid_count, count);
        return CryptoError::Success;
    }

    // CPU fallback: sequential verification
    LOG_INFO("batch_verify: using CPU fallback for %zu signatures", count);

    size_t valid_count = 0;
    for (size_t i = 0; i < count; ++i) {
        CryptoError err = mldsa65_verify(
            public_keys[i],
            std::span<const uint8_t>(messages[i]),
            signatures[i]
        );
        results[i] = (err == CryptoError::Success);
        if (results[i]) ++valid_count;
    }

    LOG_INFO("batch_verify: %zu/%zu signatures valid (CPU)", valid_count, count);
    return CryptoError::Success;
}

// ---------------------------------------------------------------------------
// PARS Identity generation
// ---------------------------------------------------------------------------

CryptoError LuxCryptoAdapter::generate_pars_identity(ParsIdentity& identity) {
    LOG_INFO("Generating new PARS identity...");

    // Generate ML-KEM keypair for key encapsulation
    CryptoError err = mlkem768_keygen(identity.kem_public_key, identity.kem_secret_key);
    if (err != CryptoError::Success) {
        LOG_ERROR("generate_pars_identity: ML-KEM keygen failed");
        return err;
    }

    // Generate ML-DSA keypair for digital signatures
    err = mldsa65_keygen(identity.dsa_public_key, identity.dsa_secret_key);
    if (err != CryptoError::Success) {
        LOG_ERROR("generate_pars_identity: ML-DSA keygen failed");
        // Zero out the KEM keys on failure
        secure_zero(identity.kem_secret_key.data(), identity.kem_secret_key.size());
        return err;
    }

    // Derive session ID from public keys
    err = derive_session_id(
        identity.kem_public_key,
        identity.dsa_public_key,
        identity.session_id
    );

    if (err != CryptoError::Success) {
        LOG_ERROR("generate_pars_identity: session ID derivation failed");
        // Zero out secret keys on failure
        secure_zero(identity.kem_secret_key.data(), identity.kem_secret_key.size());
        secure_zero(identity.dsa_secret_key.data(), identity.dsa_secret_key.size());
        return err;
    }

    LOG_INFO("PARS identity generated successfully");
    LOG_INFO("Session ID hash: %s...", to_hex(identity.session_id.data(), 8).c_str());

    return CryptoError::Success;
}

// ---------------------------------------------------------------------------
// Session ID derivation
// ---------------------------------------------------------------------------

CryptoError LuxCryptoAdapter::derive_session_id(
    const MLKEMPublicKey& kem_public_key,
    const MLDSAPublicKey& dsa_public_key,
    SessionID& session_id) {

    if (!initialized_) {
        LOG_ERROR("derive_session_id: adapter not initialized");
        return CryptoError::GpuNotAvailable;
    }

    // Concatenate public keys: kem_pk || dsa_pk
    constexpr size_t total_size = MLKEM768_PUBLIC_KEY_SIZE + MLDSA65_PUBLIC_KEY_SIZE;
    std::vector<uint8_t> concatenated(total_size);

    std::memcpy(
        concatenated.data(),
        kem_public_key.data(),
        MLKEM768_PUBLIC_KEY_SIZE
    );
    std::memcpy(
        concatenated.data() + MLKEM768_PUBLIC_KEY_SIZE,
        dsa_public_key.data(),
        MLDSA65_PUBLIC_KEY_SIZE
    );

    // Use Blake3 to derive session ID (32 bytes output)
    int result = lux_crypto_blake3(
        concatenated.data(),
        total_size,
        session_id.data(),
        SESSION_ID_SIZE
    );

    if (result != 0) {
        LOG_ERROR("derive_session_id: Blake3 hash failed: %d", result);
        return CryptoError::InvalidInput;
    }

    LOG_DEBUG("derive_session_id: derived %s", to_hex(session_id.data(), 8).c_str());
    return CryptoError::Success;
}

// ---------------------------------------------------------------------------
// Free functions using global adapter (for compatibility)
// ---------------------------------------------------------------------------

namespace {

LuxCryptoAdapter& get_global_adapter() {
    static LuxCryptoAdapter adapter;
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        CryptoError err = adapter.init();
        if (err != CryptoError::Success) {
            LOG_ERROR("Failed to initialize global crypto adapter");
        }
    });
    return adapter;
}

}  // namespace

CryptoError init() {
    return get_global_adapter().init();
}

void shutdown() {
    // Note: shutdown is handled by static destructor
    // This is a no-op to avoid double-shutdown issues
}

CryptoError mlkem768_keygen(MLKEMPublicKey& pk, MLKEMSecretKey& sk) {
    return get_global_adapter().mlkem768_keygen(pk, sk);
}

CryptoError mlkem768_encaps(
    const MLKEMPublicKey& pk,
    MLKEMCiphertext& ct,
    MLKEMSharedSecret& ss) {
    return get_global_adapter().mlkem768_encaps(pk, ct, ss);
}

CryptoError mlkem768_decaps(
    const MLKEMSecretKey& sk,
    const MLKEMCiphertext& ct,
    MLKEMSharedSecret& ss) {
    return get_global_adapter().mlkem768_decaps(sk, ct, ss);
}

CryptoError mldsa65_keygen(MLDSAPublicKey& pk, MLDSASecretKey& sk) {
    return get_global_adapter().mldsa65_keygen(pk, sk);
}

CryptoError mldsa65_sign(
    const MLDSASecretKey& sk,
    std::span<const uint8_t> msg,
    MLDSASignature& sig) {
    return get_global_adapter().mldsa65_sign(sk, msg, sig);
}

CryptoError mldsa65_verify(
    const MLDSAPublicKey& pk,
    std::span<const uint8_t> msg,
    const MLDSASignature& sig) {
    return get_global_adapter().mldsa65_verify(pk, msg, sig);
}

CryptoError batch_verify(
    const std::vector<MLDSAPublicKey>& pks,
    const std::vector<std::vector<uint8_t>>& msgs,
    const std::vector<MLDSASignature>& sigs,
    std::vector<bool>& results) {
    return get_global_adapter().batch_verify(pks, msgs, sigs, results);
}

CryptoError generate_pars_identity(ParsIdentity& identity) {
    return get_global_adapter().generate_pars_identity(identity);
}

CryptoError derive_session_id(
    const MLKEMPublicKey& kem_pk,
    const MLDSAPublicKey& dsa_pk,
    SessionID& sid) {
    return get_global_adapter().derive_session_id(kem_pk, dsa_pk, sid);
}

// ---------------------------------------------------------------------------
// String session ID derivation ("07" + hex)
// ---------------------------------------------------------------------------

std::string derive_session_id_string(
    const MLKEMPublicKey& kem_pk,
    const MLDSAPublicKey& dsa_pk) {

    SessionID hash;
    CryptoError err = derive_session_id(kem_pk, dsa_pk, hash);
    if (err != CryptoError::Success) {
        LOG_ERROR("derive_session_id_string: hash derivation failed");
        return "";
    }

    // Format: "07" + hex(Blake3(kem_pk || dsa_pk))
    return "07" + to_hex(hash.data(), hash.size());
}

}  // namespace pars::crypto
