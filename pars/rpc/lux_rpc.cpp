// Pars Network - Lux RPC Adapter Implementation
// Replaces oxend_rpc with Lux servicenodevm communication

#include "lux_rpc.h"
#include <pars/crypto/lux_crypto_adapter.h>
#include <pars/logging/pars_logger.h>

#include <oxenmq/oxenmq.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>
#include <thread>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

static auto logcat = pars::log::Cat("lux_rpc");

namespace pars::rpc {

namespace {

// Serialize PQ identity to bytes
std::vector<uint8_t> serialize_identity(const pars::crypto::ParsIdentity& id) {
    std::vector<uint8_t> data;

    // Magic bytes "PQID"
    data.push_back('P');
    data.push_back('Q');
    data.push_back('I');
    data.push_back('D');

    // Version byte
    data.push_back(1);

    // KEM keypair
    data.insert(data.end(), id.kem.public_key.begin(), id.kem.public_key.end());
    data.insert(data.end(), id.kem.secret_key.begin(), id.kem.secret_key.end());

    // DSA keypair
    data.insert(data.end(), id.dsa.public_key.begin(), id.dsa.public_key.end());
    data.insert(data.end(), id.dsa.secret_key.begin(), id.dsa.secret_key.end());

    // Session ID (66 chars as bytes)
    for (char c : id.session_id) {
        data.push_back(static_cast<uint8_t>(c));
    }

    return data;
}

// Deserialize PQ identity from bytes
std::optional<pars::crypto::ParsIdentity> deserialize_identity(const std::vector<uint8_t>& data) {
    // Minimum size check
    constexpr size_t expected_size =
        4 +  // Magic
        1 +  // Version
        pars::crypto::MLKEM768_PUBLIC_KEY_SIZE +
        pars::crypto::MLKEM768_SECRET_KEY_SIZE +
        pars::crypto::MLDSA65_PUBLIC_KEY_SIZE +
        pars::crypto::MLDSA65_SECRET_KEY_SIZE +
        66;  // Session ID

    if (data.size() < expected_size) {
        return std::nullopt;
    }

    // Check magic
    if (data[0] != 'P' || data[1] != 'Q' || data[2] != 'I' || data[3] != 'D') {
        return std::nullopt;
    }

    // Check version
    if (data[4] != 1) {
        return std::nullopt;
    }

    pars::crypto::ParsIdentity id;
    size_t offset = 5;

    // KEM public key
    std::copy(data.begin() + offset,
              data.begin() + offset + pars::crypto::MLKEM768_PUBLIC_KEY_SIZE,
              id.kem.public_key.begin());
    offset += pars::crypto::MLKEM768_PUBLIC_KEY_SIZE;

    // KEM secret key
    std::copy(data.begin() + offset,
              data.begin() + offset + pars::crypto::MLKEM768_SECRET_KEY_SIZE,
              id.kem.secret_key.begin());
    offset += pars::crypto::MLKEM768_SECRET_KEY_SIZE;

    // DSA public key
    std::copy(data.begin() + offset,
              data.begin() + offset + pars::crypto::MLDSA65_PUBLIC_KEY_SIZE,
              id.dsa.public_key.begin());
    offset += pars::crypto::MLDSA65_PUBLIC_KEY_SIZE;

    // DSA secret key
    std::copy(data.begin() + offset,
              data.begin() + offset + pars::crypto::MLDSA65_SECRET_KEY_SIZE,
              id.dsa.secret_key.begin());
    offset += pars::crypto::MLDSA65_SECRET_KEY_SIZE;

    // Session ID
    id.session_id = std::string(data.begin() + offset, data.begin() + offset + 66);

    return id;
}

}  // anonymous namespace

std::optional<pars::crypto::ParsIdentity> get_pq_keys(
        std::string_view lux_rpc_address,
        const fs::path& data_dir,
        std::function<bool()> keep_trying) {

    // First try to load existing identity
    if (auto id = load_pq_identity(data_dir)) {
        pars::log::info(logcat, "Loaded existing PQ identity from disk");
        pars::log::info(logcat, "Session ID: {}", id->session_id);
        return id;
    }

    pars::log::info(logcat, "No existing PQ identity found, generating new one...");

    // Generate new PQ identity
    auto id = pars::crypto::generate_pars_identity();
    if (!id) {
        pars::log::error(logcat, "Failed to generate PQ identity");
        return std::nullopt;
    }

    pars::log::info(logcat, "Generated new PQ identity");
    pars::log::info(logcat, "Session ID: {}", id->session_id);

    // Save to disk
    if (!save_pq_identity(*id, data_dir)) {
        pars::log::warning(logcat, "Failed to save PQ identity to disk");
        // Continue anyway - we can regenerate if needed
    }

    // Register with Lux if address provided
    if (!lux_rpc_address.empty()) {
        int attempts = 0;
        while (keep_trying == nullptr || keep_trying()) {
            attempts++;
            pars::log::info(logcat, "Attempting to register with Lux servicenodevm (attempt {})", attempts);

            if (register_with_lux(lux_rpc_address, *id, 0)) {
                pars::log::info(logcat, "Successfully registered with Lux servicenodevm");
                break;
            }

            pars::log::warning(logcat, "Failed to register with Lux, retrying in 5s...");
            std::this_thread::sleep_for(5s);
        }
    }

    return id;
}

bool save_pq_identity(
        const pars::crypto::ParsIdentity& identity,
        const fs::path& data_dir) {

    auto path = data_dir / PQ_IDENTITY_FILE;

    auto data = serialize_identity(identity);

    // Write atomically via temp file
    auto tmp_path = path;
    tmp_path += ".tmp";

    std::ofstream out(tmp_path, std::ios::binary);
    if (!out) {
        pars::log::error(logcat, "Failed to open {} for writing", tmp_path.string());
        return false;
    }

    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.close();

    if (!out) {
        pars::log::error(logcat, "Failed to write PQ identity to {}", tmp_path.string());
        return false;
    }

    // Atomic rename
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
        pars::log::error(logcat, "Failed to rename {} to {}: {}",
                        tmp_path.string(), path.string(), ec.message());
        return false;
    }

    // Set restrictive permissions (600)
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, ec);
    if (ec) {
        pars::log::warning(logcat, "Failed to set permissions on {}: {}",
                          path.string(), ec.message());
    }

    pars::log::info(logcat, "Saved PQ identity to {}", path.string());
    return true;
}

std::optional<pars::crypto::ParsIdentity> load_pq_identity(const fs::path& data_dir) {
    auto path = data_dir / PQ_IDENTITY_FILE;

    if (!fs::exists(path)) {
        return std::nullopt;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        pars::log::error(logcat, "Failed to open {} for reading", path.string());
        return std::nullopt;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());

    return deserialize_identity(data);
}

bool register_with_lux(
        std::string_view lux_rpc_address,
        const pars::crypto::ParsIdentity& identity,
        uint64_t stake_amount) {

    // Connect to Lux servicenodevm via OxenMQ
    oxenmq::OxenMQ omq{};
    omq.start();

    auto conn = omq.connect_remote(
        oxenmq::address{std::string{lux_rpc_address}},
        [](oxenmq::ConnectionID) {},  // on connect
        [](oxenmq::ConnectionID, std::string_view reason) {
            pars::log::error(logcat, "Failed to connect to Lux: {}", reason);
        },
        oxenmq::AuthLevel::none);

    std::promise<bool> result_promise;
    auto result_future = result_promise.get_future();

    // Prepare registration request
    nlohmann::json reg_request;
    reg_request["session_id"] = identity.session_id;
    reg_request["kem_pubkey"] = oxenmq::to_hex(identity.kem.public_key.begin(),
                                                identity.kem.public_key.end());
    reg_request["dsa_pubkey"] = oxenmq::to_hex(identity.dsa.public_key.begin(),
                                                identity.dsa.public_key.end());
    reg_request["stake_amount"] = stake_amount;

    omq.request(conn, "servicenode.register_pq",
        [&result_promise](bool success, std::vector<std::string> data) {
            if (success && !data.empty()) {
                try {
                    auto response = nlohmann::json::parse(data[0]);
                    if (response.value("status", "") == "ok") {
                        result_promise.set_value(true);
                        return;
                    }
                    pars::log::error(logcat, "Registration failed: {}",
                                    response.value("error", "unknown error"));
                } catch (const std::exception& e) {
                    pars::log::error(logcat, "Failed to parse registration response: {}", e.what());
                }
            }
            result_promise.set_value(false);
        },
        reg_request.dump());

    // Wait for response with timeout
    if (result_future.wait_for(10s) == std::future_status::timeout) {
        pars::log::error(logcat, "Registration request timed out");
        return false;
    }

    return result_future.get();
}

std::string get_swarm_members(std::string_view lux_rpc_address) {
    oxenmq::OxenMQ omq{};
    omq.start();

    auto conn = omq.connect_remote(
        oxenmq::address{std::string{lux_rpc_address}},
        [](oxenmq::ConnectionID) {},
        [](oxenmq::ConnectionID, std::string_view reason) {
            pars::log::error(logcat, "Failed to connect to Lux: {}", reason);
        },
        oxenmq::AuthLevel::none);

    std::promise<std::string> result_promise;
    auto result_future = result_promise.get_future();

    omq.request(conn, "servicenode.get_swarm_members",
        [&result_promise](bool success, std::vector<std::string> data) {
            if (success && !data.empty()) {
                result_promise.set_value(data[0]);
            } else {
                result_promise.set_value("{}");
            }
        });

    if (result_future.wait_for(10s) == std::future_status::timeout) {
        pars::log::error(logcat, "Get swarm members request timed out");
        return "{}";
    }

    return result_future.get();
}

uint64_t get_block_height(std::string_view lux_rpc_address) {
    oxenmq::OxenMQ omq{};
    omq.start();

    auto conn = omq.connect_remote(
        oxenmq::address{std::string{lux_rpc_address}},
        [](oxenmq::ConnectionID) {},
        [](oxenmq::ConnectionID, std::string_view) {},
        oxenmq::AuthLevel::none);

    std::promise<uint64_t> result_promise;
    auto result_future = result_promise.get_future();

    omq.request(conn, "servicenode.get_height",
        [&result_promise](bool success, std::vector<std::string> data) {
            if (success && !data.empty()) {
                try {
                    auto response = nlohmann::json::parse(data[0]);
                    result_promise.set_value(response.value("height", 0ULL));
                    return;
                } catch (...) {}
            }
            result_promise.set_value(0);
        });

    if (result_future.wait_for(5s) == std::future_status::timeout) {
        return 0;
    }

    return result_future.get();
}

bool send_uptime_proof(
        std::string_view lux_rpc_address,
        const pars::crypto::ParsIdentity& identity) {

    oxenmq::OxenMQ omq{};
    omq.start();

    auto conn = omq.connect_remote(
        oxenmq::address{std::string{lux_rpc_address}},
        [](oxenmq::ConnectionID) {},
        [](oxenmq::ConnectionID, std::string_view reason) {
            pars::log::error(logcat, "Failed to connect to Lux: {}", reason);
        },
        oxenmq::AuthLevel::none);

    // Create uptime proof with PQ signature
    auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<uint8_t> proof_data;

    // Add timestamp
    for (int i = 0; i < 8; i++) {
        proof_data.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));
    }

    // Add session ID
    for (char c : identity.session_id) {
        proof_data.push_back(static_cast<uint8_t>(c));
    }

    // Sign with ML-DSA
    auto signature = pars::crypto::mldsa65_sign(proof_data, identity.dsa.secret_key);
    if (!signature) {
        pars::log::error(logcat, "Failed to sign uptime proof");
        return false;
    }

    nlohmann::json proof_request;
    proof_request["session_id"] = identity.session_id;
    proof_request["timestamp"] = timestamp;
    proof_request["signature"] = oxenmq::to_hex(signature->begin(), signature->end());

    std::promise<bool> result_promise;
    auto result_future = result_promise.get_future();

    omq.request(conn, "servicenode.uptime_proof",
        [&result_promise](bool success, std::vector<std::string> data) {
            if (success && !data.empty()) {
                try {
                    auto response = nlohmann::json::parse(data[0]);
                    result_promise.set_value(response.value("status", "") == "ok");
                    return;
                } catch (...) {}
            }
            result_promise.set_value(false);
        },
        proof_request.dump());

    if (result_future.wait_for(5s) == std::future_status::timeout) {
        pars::log::warning(logcat, "Uptime proof request timed out");
        return false;
    }

    return result_future.get();
}

}  // namespace pars::rpc
