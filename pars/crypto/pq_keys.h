// Pars Network - Post-Quantum Key Types
// Uses ML-KEM-768 and ML-DSA-65 via lux/crypto
#pragma once

#include "lux_crypto_adapter.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace pars::crypto {

// Size constants for ML-KEM-768
constexpr size_t MLKEM768_PUBLIC_KEY_SIZE = 1184;
constexpr size_t MLKEM768_SECRET_KEY_SIZE = 2400;
constexpr size_t MLKEM768_CIPHERTEXT_SIZE = 1088;
constexpr size_t MLKEM768_SHARED_SECRET_SIZE = 32;

// Size constants for ML-DSA-65
constexpr size_t MLDSA65_PUBLIC_KEY_SIZE = 1952;
constexpr size_t MLDSA65_SECRET_KEY_SIZE = 4032;
constexpr size_t MLDSA65_SIGNATURE_SIZE = 3309;

// Key types from lux/crypto adapter
using mlkem768_public_key = std::array<uint8_t, MLKEM768_PUBLIC_KEY_SIZE>;
using mlkem768_secret_key = std::array<uint8_t, MLKEM768_SECRET_KEY_SIZE>;
using mlkem768_ciphertext = std::array<uint8_t, MLKEM768_CIPHERTEXT_SIZE>;
using shared_secret = std::array<uint8_t, MLKEM768_SHARED_SECRET_SIZE>;
using mldsa65_public_key = std::array<uint8_t, MLDSA65_PUBLIC_KEY_SIZE>;
using mldsa65_secret_key = std::array<uint8_t, MLDSA65_SECRET_KEY_SIZE>;
using mldsa65_signature = std::array<uint8_t, MLDSA65_SIGNATURE_SIZE>;

// Key pair structures
struct MLKEMKeyPair {
    mlkem768_public_key public_key;
    mlkem768_secret_key secret_key;
};

struct MLDSAKeyPair {
    mldsa65_public_key public_key;
    mldsa65_secret_key secret_key;
};

// Combined identity for Pars nodes
struct ParsIdentity {
    MLKEMKeyPair kem;
    MLDSAKeyPair dsa;
};

// Encapsulation result
struct EncapsulationResult {
    mlkem768_ciphertext ciphertext;
    shared_secret secret;
};

// Session ID constants
constexpr std::string_view PARS_SESSION_ID_PREFIX = "07";

inline bool is_pars_session_id(std::string_view id) {
    return id.size() == 66 && id.substr(0, 2) == PARS_SESSION_ID_PREFIX;
}

inline bool is_legacy_session_id(std::string_view id) {
    return id.size() == 66 && id.substr(0, 2) == "05";
}

// Helper to convert first N bytes of a key to hex for logging
inline std::string to_hex_prefix(const auto& key, size_t prefix_len = 16) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(prefix_len * 2);
    for (size_t i = 0; i < prefix_len && i < key.size(); i++) {
        result.push_back(hex_chars[(key[i] >> 4) & 0xF]);
        result.push_back(hex_chars[key[i] & 0xF]);
    }
    return result;
}

// Pars service node contact info (replaces oxenss::snode::contact)
struct pars_contact {
    std::string session_id;              // "07" + 64 hex chars
    mldsa65_public_key dsa_pubkey;       // For signature verification
    mlkem768_public_key kem_pubkey;      // For encrypted messages
    std::string ip;
    uint16_t https_port;
    uint16_t quic_port;
    std::array<uint16_t, 3> version;

    // Validate that session ID matches the public keys
    bool validate() const {
        auto derived_id = derive_session_id(kem_pubkey, dsa_pubkey);
        return session_id == derived_id;
    }
};

}  // namespace pars::crypto
