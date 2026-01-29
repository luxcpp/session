// lux_crypto_adapter.h - Bridge session::pq to lux/crypto
// SPDX-License-Identifier: MIT
//
// Provides session::pq compatible wrappers routing to lux_crypto_* functions
// with GPU acceleration via Metal for ML-KEM-768 and ML-DSA-65

#ifndef PARS_CRYPTO_LUX_CRYPTO_ADAPTER_H
#define PARS_CRYPTO_LUX_CRYPTO_ADAPTER_H

#include <lux/crypto/crypto.h>
#include <lux/crypto/metal_mldsa.h>
#include <lux/crypto/metal_mlkem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace pars::crypto {

// ML-KEM-768 constants (NIST Level 3)
constexpr size_t MLKEM768_PUBLIC_KEY_SIZE  = 1184;
constexpr size_t MLKEM768_SECRET_KEY_SIZE  = 2400;
constexpr size_t MLKEM768_CIPHERTEXT_SIZE  = 1088;
constexpr size_t MLKEM768_SHARED_SECRET_SIZE = 32;

// ML-DSA-65 constants (NIST Level 3)
constexpr size_t MLDSA65_PUBLIC_KEY_SIZE   = 1952;
constexpr size_t MLDSA65_SECRET_KEY_SIZE   = 4032;
constexpr size_t MLDSA65_SIGNATURE_SIZE    = 3309;

// Session identity sizes
constexpr size_t SESSION_ID_SIZE = 32;  // Blake2b-256 output

// Error codes
enum class CryptoError : int {
    Success = 0,
    InvalidInput = -1,
    KeygenFailed = -2,
    EncapsFailed = -3,
    DecapsFailed = -4,
    SignFailed = -5,
    VerifyFailed = -6,
    GpuInitFailed = -7,
    GpuNotAvailable = -8,
    BatchVerifyFailed = -9,
};

// Type aliases for clarity
using MLKEMPublicKey = std::array<uint8_t, MLKEM768_PUBLIC_KEY_SIZE>;
using MLKEMSecretKey = std::array<uint8_t, MLKEM768_SECRET_KEY_SIZE>;
using MLKEMCiphertext = std::array<uint8_t, MLKEM768_CIPHERTEXT_SIZE>;
using MLKEMSharedSecret = std::array<uint8_t, MLKEM768_SHARED_SECRET_SIZE>;

using MLDSAPublicKey = std::array<uint8_t, MLDSA65_PUBLIC_KEY_SIZE>;
using MLDSASecretKey = std::array<uint8_t, MLDSA65_SECRET_KEY_SIZE>;
using MLDSASignature = std::array<uint8_t, MLDSA65_SIGNATURE_SIZE>;

using SessionID = std::array<uint8_t, SESSION_ID_SIZE>;

// Forward declarations for GPU context opaque types
struct GPUContext;

// PARS identity: combined ML-KEM + ML-DSA keypair
struct ParsIdentity {
    MLKEMPublicKey kem_public_key;
    MLKEMSecretKey kem_secret_key;
    MLDSAPublicKey dsa_public_key;
    MLDSASecretKey dsa_secret_key;
    SessionID session_id;
};

// GPU acceleration context manager
class LuxCryptoAdapter {
public:
    LuxCryptoAdapter() = default;
    ~LuxCryptoAdapter();

    // Non-copyable, movable
    LuxCryptoAdapter(const LuxCryptoAdapter&) = delete;
    LuxCryptoAdapter& operator=(const LuxCryptoAdapter&) = delete;
    LuxCryptoAdapter(LuxCryptoAdapter&&) noexcept;
    LuxCryptoAdapter& operator=(LuxCryptoAdapter&&) noexcept;

    // Initialization and shutdown
    [[nodiscard]] CryptoError init();
    void shutdown();
    [[nodiscard]] bool is_gpu_available() const noexcept;

    // ML-KEM-768 operations
    [[nodiscard]] CryptoError mlkem768_keygen(
        MLKEMPublicKey& public_key,
        MLKEMSecretKey& secret_key
    );

    [[nodiscard]] CryptoError mlkem768_encaps(
        const MLKEMPublicKey& public_key,
        MLKEMCiphertext& ciphertext,
        MLKEMSharedSecret& shared_secret
    );

    [[nodiscard]] CryptoError mlkem768_decaps(
        const MLKEMSecretKey& secret_key,
        const MLKEMCiphertext& ciphertext,
        MLKEMSharedSecret& shared_secret
    );

    // ML-DSA-65 operations
    [[nodiscard]] CryptoError mldsa65_keygen(
        MLDSAPublicKey& public_key,
        MLDSASecretKey& secret_key
    );

    [[nodiscard]] CryptoError mldsa65_sign(
        const MLDSASecretKey& secret_key,
        std::span<const uint8_t> message,
        MLDSASignature& signature
    );

    [[nodiscard]] CryptoError mldsa65_verify(
        const MLDSAPublicKey& public_key,
        std::span<const uint8_t> message,
        const MLDSASignature& signature
    );

    // GPU-accelerated batch verification
    [[nodiscard]] CryptoError batch_verify(
        const std::vector<MLDSAPublicKey>& public_keys,
        const std::vector<std::vector<uint8_t>>& messages,
        const std::vector<MLDSASignature>& signatures,
        std::vector<bool>& results
    );

    // PARS identity generation
    [[nodiscard]] CryptoError generate_pars_identity(ParsIdentity& identity);

    // Session ID derivation (Blake2b of concatenated public keys)
    [[nodiscard]] CryptoError derive_session_id(
        const MLKEMPublicKey& kem_public_key,
        const MLDSAPublicKey& dsa_public_key,
        SessionID& session_id
    );

private:
    MetalMLDSAContext* mldsa_ctx_ = nullptr;
    MetalMLKEMContext* mlkem_ctx_ = nullptr;
    bool initialized_ = false;
    bool gpu_available_ = false;
};

// Implementation

inline LuxCryptoAdapter::~LuxCryptoAdapter() {
    shutdown();
}

inline LuxCryptoAdapter::LuxCryptoAdapter(LuxCryptoAdapter&& other) noexcept
    : mldsa_ctx_(other.mldsa_ctx_)
    , mlkem_ctx_(other.mlkem_ctx_)
    , initialized_(other.initialized_)
    , gpu_available_(other.gpu_available_)
{
    other.mldsa_ctx_ = nullptr;
    other.mlkem_ctx_ = nullptr;
    other.initialized_ = false;
    other.gpu_available_ = false;
}

inline LuxCryptoAdapter& LuxCryptoAdapter::operator=(LuxCryptoAdapter&& other) noexcept {
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

inline CryptoError LuxCryptoAdapter::init() {
    if (initialized_) {
        return CryptoError::Success;
    }

    // Initialize lux crypto library
    if (lux_crypto_init() != 0) {
        return CryptoError::GpuInitFailed;
    }

    // Create Metal GPU contexts for accelerated operations
    mldsa_ctx_ = metal_mldsa_context_create();
    mlkem_ctx_ = metal_mlkem_context_create();

    gpu_available_ = (mldsa_ctx_ != nullptr) && (mlkem_ctx_ != nullptr);
    initialized_ = true;

    return CryptoError::Success;
}

inline void LuxCryptoAdapter::shutdown() {
    if (!initialized_) {
        return;
    }

    if (mldsa_ctx_) {
        metal_mldsa_context_destroy(mldsa_ctx_);
        mldsa_ctx_ = nullptr;
    }

    if (mlkem_ctx_) {
        metal_mlkem_context_destroy(mlkem_ctx_);
        mlkem_ctx_ = nullptr;
    }

    lux_crypto_shutdown();
    initialized_ = false;
    gpu_available_ = false;
}

inline bool LuxCryptoAdapter::is_gpu_available() const noexcept {
    return gpu_available_;
}

inline CryptoError LuxCryptoAdapter::mlkem768_keygen(
    MLKEMPublicKey& public_key,
    MLKEMSecretKey& secret_key
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    int result;
    if (gpu_available_) {
        result = metal_mlkem768_keygen(
            mlkem_ctx_,
            public_key.data(),
            secret_key.data()
        );
    } else {
        result = lux_crypto_mlkem768_keygen(
            public_key.data(),
            secret_key.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::KeygenFailed;
}

inline CryptoError LuxCryptoAdapter::mlkem768_encaps(
    const MLKEMPublicKey& public_key,
    MLKEMCiphertext& ciphertext,
    MLKEMSharedSecret& shared_secret
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    int result;
    if (gpu_available_) {
        result = metal_mlkem768_encaps(
            mlkem_ctx_,
            public_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    } else {
        result = lux_crypto_mlkem768_encaps(
            public_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::EncapsFailed;
}

inline CryptoError LuxCryptoAdapter::mlkem768_decaps(
    const MLKEMSecretKey& secret_key,
    const MLKEMCiphertext& ciphertext,
    MLKEMSharedSecret& shared_secret
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    int result;
    if (gpu_available_) {
        result = metal_mlkem768_decaps(
            mlkem_ctx_,
            secret_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    } else {
        result = lux_crypto_mlkem768_decaps(
            secret_key.data(),
            ciphertext.data(),
            shared_secret.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::DecapsFailed;
}

inline CryptoError LuxCryptoAdapter::mldsa65_keygen(
    MLDSAPublicKey& public_key,
    MLDSASecretKey& secret_key
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    int result;
    if (gpu_available_) {
        result = metal_mldsa65_keygen(
            mldsa_ctx_,
            public_key.data(),
            secret_key.data()
        );
    } else {
        result = lux_crypto_mldsa65_keygen(
            public_key.data(),
            secret_key.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::KeygenFailed;
}

inline CryptoError LuxCryptoAdapter::mldsa65_sign(
    const MLDSASecretKey& secret_key,
    std::span<const uint8_t> message,
    MLDSASignature& signature
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    if (message.empty()) {
        return CryptoError::InvalidInput;
    }

    int result;
    if (gpu_available_) {
        result = metal_mldsa65_sign(
            mldsa_ctx_,
            secret_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    } else {
        result = lux_crypto_mldsa65_sign(
            secret_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::SignFailed;
}

inline CryptoError LuxCryptoAdapter::mldsa65_verify(
    const MLDSAPublicKey& public_key,
    std::span<const uint8_t> message,
    const MLDSASignature& signature
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    if (message.empty()) {
        return CryptoError::InvalidInput;
    }

    int result;
    if (gpu_available_) {
        result = metal_mldsa65_verify(
            mldsa_ctx_,
            public_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    } else {
        result = lux_crypto_mldsa65_verify(
            public_key.data(),
            message.data(),
            message.size(),
            signature.data()
        );
    }

    return (result == 0) ? CryptoError::Success : CryptoError::VerifyFailed;
}

inline CryptoError LuxCryptoAdapter::batch_verify(
    const std::vector<MLDSAPublicKey>& public_keys,
    const std::vector<std::vector<uint8_t>>& messages,
    const std::vector<MLDSASignature>& signatures,
    std::vector<bool>& results
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    const size_t count = public_keys.size();
    if (count == 0 || messages.size() != count || signatures.size() != count) {
        return CryptoError::InvalidInput;
    }

    results.resize(count);

    // GPU batch verification path
    if (gpu_available_ && count > 1) {
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

        int result = metal_mldsa65_batch_verify(
            mldsa_ctx_,
            pk_ptrs.data(),
            msg_ptrs.data(),
            msg_lens.data(),
            sig_ptrs.data(),
            count,
            batch_results.data()
        );

        if (result != 0) {
            return CryptoError::BatchVerifyFailed;
        }

        for (size_t i = 0; i < count; ++i) {
            results[i] = (batch_results[i] == 0);
        }

        return CryptoError::Success;
    }

    // Fallback: sequential verification
    for (size_t i = 0; i < count; ++i) {
        CryptoError err = mldsa65_verify(
            public_keys[i],
            std::span<const uint8_t>(messages[i]),
            signatures[i]
        );
        results[i] = (err == CryptoError::Success);
    }

    return CryptoError::Success;
}

inline CryptoError LuxCryptoAdapter::generate_pars_identity(ParsIdentity& identity) {
    // Generate ML-KEM keypair for key encapsulation
    CryptoError err = mlkem768_keygen(identity.kem_public_key, identity.kem_secret_key);
    if (err != CryptoError::Success) {
        return err;
    }

    // Generate ML-DSA keypair for digital signatures
    err = mldsa65_keygen(identity.dsa_public_key, identity.dsa_secret_key);
    if (err != CryptoError::Success) {
        return err;
    }

    // Derive session ID from public keys
    return derive_session_id(
        identity.kem_public_key,
        identity.dsa_public_key,
        identity.session_id
    );
}

inline CryptoError LuxCryptoAdapter::derive_session_id(
    const MLKEMPublicKey& kem_public_key,
    const MLDSAPublicKey& dsa_public_key,
    SessionID& session_id
) {
    if (!initialized_) {
        return CryptoError::GpuNotAvailable;
    }

    // Concatenate public keys for hashing
    constexpr size_t total_size = MLKEM768_PUBLIC_KEY_SIZE + MLDSA65_PUBLIC_KEY_SIZE;
    std::array<uint8_t, total_size> concatenated;

    std::copy(
        kem_public_key.begin(),
        kem_public_key.end(),
        concatenated.begin()
    );
    std::copy(
        dsa_public_key.begin(),
        dsa_public_key.end(),
        concatenated.begin() + MLKEM768_PUBLIC_KEY_SIZE
    );

    // Use Blake2b-256 to derive session ID
    int result = lux_crypto_blake2b(
        concatenated.data(),
        total_size,
        session_id.data(),
        SESSION_ID_SIZE
    );

    return (result == 0) ? CryptoError::Success : CryptoError::InvalidInput;
}

// Convenience free functions for compatibility with session::pq API

inline CryptoError init() {
    static LuxCryptoAdapter adapter;
    return adapter.init();
}

inline void shutdown() {
    // Handled by static adapter destructor
}

// Global adapter instance for free functions
inline LuxCryptoAdapter& get_adapter() {
    static LuxCryptoAdapter adapter;
    return adapter;
}

inline CryptoError mlkem768_keygen(MLKEMPublicKey& pk, MLKEMSecretKey& sk) {
    return get_adapter().mlkem768_keygen(pk, sk);
}

inline CryptoError mlkem768_encaps(
    const MLKEMPublicKey& pk,
    MLKEMCiphertext& ct,
    MLKEMSharedSecret& ss
) {
    return get_adapter().mlkem768_encaps(pk, ct, ss);
}

inline CryptoError mlkem768_decaps(
    const MLKEMSecretKey& sk,
    const MLKEMCiphertext& ct,
    MLKEMSharedSecret& ss
) {
    return get_adapter().mlkem768_decaps(sk, ct, ss);
}

inline CryptoError mldsa65_keygen(MLDSAPublicKey& pk, MLDSASecretKey& sk) {
    return get_adapter().mldsa65_keygen(pk, sk);
}

inline CryptoError mldsa65_sign(
    const MLDSASecretKey& sk,
    std::span<const uint8_t> msg,
    MLDSASignature& sig
) {
    return get_adapter().mldsa65_sign(sk, msg, sig);
}

inline CryptoError mldsa65_verify(
    const MLDSAPublicKey& pk,
    std::span<const uint8_t> msg,
    const MLDSASignature& sig
) {
    return get_adapter().mldsa65_verify(pk, msg, sig);
}

inline CryptoError batch_verify(
    const std::vector<MLDSAPublicKey>& pks,
    const std::vector<std::vector<uint8_t>>& msgs,
    const std::vector<MLDSASignature>& sigs,
    std::vector<bool>& results
) {
    return get_adapter().batch_verify(pks, msgs, sigs, results);
}

inline CryptoError generate_pars_identity(ParsIdentity& identity) {
    return get_adapter().generate_pars_identity(identity);
}

inline CryptoError derive_session_id(
    const MLKEMPublicKey& kem_pk,
    const MLDSAPublicKey& dsa_pk,
    SessionID& sid
) {
    return get_adapter().derive_session_id(kem_pk, dsa_pk, sid);
}

// Derive session ID as string: "07" + hex(Blake3(kem_pk || dsa_pk))
std::string derive_session_id_string(
    const MLKEMPublicKey& kem_pk,
    const MLDSAPublicKey& dsa_pk);

}  // namespace pars::crypto

#endif  // PARS_CRYPTO_LUX_CRYPTO_ADAPTER_H
