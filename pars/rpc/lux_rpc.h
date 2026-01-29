// Pars Network - Lux RPC Adapter
// Replaces oxend_rpc with Lux servicenodevm communication
#pragma once

#include <pars/crypto/pq_keys.h>

#include <filesystem>
#include <functional>
#include <optional>
#include <string_view>

namespace pars::rpc {

// Path to store PQ identity keys
constexpr std::string_view PQ_IDENTITY_FILE = "pq_identity.dat";

/// Get or generate PQ keys for this service node
///
/// First tries to load existing keys from disk.
/// If not found, generates new PQ identity and saves it.
/// Optionally registers with Lux servicenodevm if lux_rpc_address is provided.
///
/// @param lux_rpc_address  Address of Lux node RPC (e.g. "tcp://127.0.0.1:22025")
/// @param data_dir         Directory to store identity files
/// @param keep_trying      Optional callback, returns false to abort
/// @returns PQ identity or nullopt on failure
std::optional<pars::crypto::ParsIdentity> get_pq_keys(
        std::string_view lux_rpc_address,
        const std::filesystem::path& data_dir,
        std::function<bool()> keep_trying = nullptr);

/// Save PQ identity to disk
/// @param identity The identity to save
/// @param data_dir Directory to save to
/// @returns true on success
bool save_pq_identity(
        const pars::crypto::ParsIdentity& identity,
        const std::filesystem::path& data_dir);

/// Load PQ identity from disk
/// @param data_dir Directory to load from
/// @returns identity or nullopt if not found
std::optional<pars::crypto::ParsIdentity> load_pq_identity(
        const std::filesystem::path& data_dir);

/// Register this service node with Lux servicenodevm
/// @param lux_rpc_address  Lux node RPC address
/// @param identity         Our PQ identity to register
/// @param stake_amount     Amount to stake (in nanoLUX)
/// @returns true on success
bool register_with_lux(
        std::string_view lux_rpc_address,
        const pars::crypto::ParsIdentity& identity,
        uint64_t stake_amount);

/// Get current swarm membership from Lux servicenodevm
/// @param lux_rpc_address  Lux node RPC address
/// @returns JSON response with swarm data
std::string get_swarm_members(std::string_view lux_rpc_address);

/// Get block height from Lux chain
/// @param lux_rpc_address  Lux node RPC address
/// @returns current block height
uint64_t get_block_height(std::string_view lux_rpc_address);

/// Send uptime proof to Lux servicenodevm
/// @param lux_rpc_address  Lux node RPC address
/// @param identity         Our PQ identity
/// @returns true on success
bool send_uptime_proof(
        std::string_view lux_rpc_address,
        const pars::crypto::ParsIdentity& identity);

}  // namespace pars::rpc
