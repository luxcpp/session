// Pars Network Storage Server
// Post-Quantum E2E Secure Messaging Node
//
// Replaces oxend with Lux servicenodevm for validator consensus
// Uses ML-KEM-768 and ML-DSA-65 for all cryptographic operations

#include "command_line.h"
#include <pars/common/mainnet.h>
#include <pars/crypto/pq_channel_encryption.hpp>
#include <pars/crypto/pq_keys.h>
#include <pars/logging/pars_logger.h>
#include <pars/rpc/lux_rpc.h>
#include <pars/rpc/request_handler.h>
#include <pars/server/https.h>
#include <pars/server/omq.h>
#include <pars/server/quic.h>
#include <pars/server/server_certificates.h>
#include <pars/snode/service_node.h>
#include <pars/snode/swarm.h>
#include <pars/version.h>

// Post-quantum crypto
#include <session/pq/pq_crypto.hpp>

#include <oxenmq/oxenmq.h>
#include <sodium/core.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <variant>
#include <vector>

extern "C" {
#include <sys/types.h>
#include <unistd.h>

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
}

namespace fs = std::filesystem;

static auto logcat = pars::log::Cat("parsd");

std::atomic<int> signalled = 0;
extern "C" void handle_signal(int sig) {
    signalled = sig;
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    using namespace pars;

    auto parsed = cli::parse_cli_args(argc, argv);
    if (auto* code = std::get_if<int>(&parsed))
        return *code;

    auto& options = std::get<cli::command_line_options>(parsed);

    if (!fs::exists(options.data_dir))
        fs::create_directories(options.data_dir);

    log::Level log_level;
    try {
        log_level = log::level_from_string(options.log_level);
    } catch (const std::invalid_argument& e) {
        log::critical(
                logcat,
                "{}; supported levels: trace, debug, info, warn, error, critical, off",
                e.what(),
                options.log_level);
        return EXIT_FAILURE;
    }

    logging::init(options.data_dir, log_level);

    if (options.testnet) {
        is_mainnet = false;
        log::warning(logcat, "Starting in testnet mode, make sure this is intentional!");
    }

    // Print Pars version and PQ crypto info
    log::info(logcat, "═══════════════════════════════════════════════════════════════");
    log::info(logcat, "║         PARS NETWORK - Post-Quantum Storage Server          ║");
    log::info(logcat, "═══════════════════════════════════════════════════════════════");
    log::info(logcat, "{}", PARS_STORAGE_VERSION_INFO);
    log::info(logcat, "Post-Quantum Cryptography:");
    log::info(logcat, "  - Key Encapsulation: ML-KEM-768 (NIST FIPS 203)");
    log::info(logcat, "  - Digital Signatures: ML-DSA-65 (NIST FIPS 204)");
    log::info(logcat, "  - Symmetric Encryption: XChaCha20-Poly1305");
    log::info(logcat, "  - Hashing: Blake2b-256");
    log::info(logcat, "═══════════════════════════════════════════════════════════════");

    log::info(logcat, "Setting log level to {}", options.log_level);
    log::info(logcat, "Setting database location to {}", util::to_sv(options.data_dir.u8string()));
    log::info(logcat, "Connecting to Lux servicenodevm @ {}", options.lux_rpc);

    // Initialize PQ crypto library
    if (!session::pq::init()) {
        log::error(logcat, "Could not initialize post-quantum crypto library (liboqs)");
        return EXIT_FAILURE;
    }
    log::info(logcat, "Post-quantum crypto initialized successfully");

    // Initialize libsodium for symmetric crypto
    if (sodium_init() != 0) {
        log::error(logcat, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (const auto fd_limit = sysconf(_SC_OPEN_MAX); fd_limit != -1) {
        log::debug(logcat, "Open file descriptor limit: {}", fd_limit);
    } else {
        log::debug(logcat, "Open descriptor limit: N/A");
    }

    try {
        std::vector<session::pq::mlkem768_public_key> stats_access_keys;
        for (const auto& key : options.stats_access_keys) {
            // TODO: Parse hex keys
            log::info(logcat, "Stats access key: {}", key);
        }

        // Get PQ keys from Lux servicenodevm (or generate new identity)
        auto pq_identity = rpc::get_pq_keys(options.lux_rpc, options.data_dir, [] { return signalled == 0; });

        if (signalled) {
            log::error(logcat, "Received signal {}, aborting startup", signalled.load());
            return EXIT_FAILURE;
        }

        if (!pq_identity) {
            log::error(logcat, "Failed to obtain PQ identity from Lux or generate new one");
            return EXIT_FAILURE;
        }

        snode::contact me{
                oxen::quic::ipv4{0},
                options.https_port,
                options.omq_quic_port,
                PARS_STORAGE_VERSION,
                pq_identity->dsa.public_key,
                pq_identity->kem.public_key};

        log::info(logcat, "Retrieved/generated PQ identity; our Pars keys are:");
        log::info(logcat, "- Session ID: {}", pq_identity->session_id);
        log::info(logcat, "- ML-DSA pubkey: {}... ({} bytes)",
                  to_hex_prefix(pq_identity->dsa.public_key, 32),
                  pq_identity->dsa.public_key.size());
        log::info(logcat, "- ML-KEM pubkey: {}... ({} bytes)",
                  to_hex_prefix(pq_identity->kem.public_key, 32),
                  pq_identity->kem.public_key.size());

        crypto::PQChannelEncryption channel_encryption{*pq_identity};

        auto ssl_cert = options.data_dir / "cert.pem";
        auto ssl_key = options.data_dir / "key.pem";
        auto ssl_dh = options.data_dir / "dh.pem";
        if (!exists(ssl_cert) || !exists(ssl_key))
            generate_cert(ssl_cert, ssl_key);
        if (!exists(ssl_dh))
            generate_dh_pem(ssl_dh);

        // Set up oxenmq (used for internal comms, still quantum-safe with PQ layer)
        auto oxenmq_server_ptr = std::make_unique<server::OMQ>(*pq_identity, stats_access_keys);
        auto& oxenmq_server = *oxenmq_server_ptr;

        snode::ServiceNode service_node{
                *pq_identity, me, oxenmq_server, options.data_dir, options.force_start};

        rpc::RequestHandler request_handler{service_node, channel_encryption, pq_identity->dsa.secret_key};

        rpc::RateLimiter rate_limiter{*oxenmq_server};

        std::vector<std::tuple<std::string, uint16_t, bool>> https_bind;
        std::vector<oxen::quic::Address> quic_bind;
#ifdef IPV6_V6ONLY
        https_bind.emplace_back("::", options.https_port, true);
        quic_bind.emplace_back("::", options.omq_quic_port);
        quic_bind.back().dual_stack = true;
#else
        https_bind.emplace_back("0.0.0.0", options.https_port, true);
        https_bind.emplace_back("::", options.https_port, true);

        quic_bind.emplace_back("0.0.0.0", options.omq_quic_port);
        quic_bind.emplace_back("::", options.omq_quic_port);
        quic_bind.back().dual_stack = false;
#endif

        server::HTTPS https_server{
                service_node,
                request_handler,
                rate_limiter,
                std::move(https_bind),
                ssl_cert,
                ssl_key,
                ssl_dh,
                *pq_identity};

        auto quic = std::make_unique<server::QUIC>(
                service_node, request_handler, rate_limiter, std::move(quic_bind), pq_identity->dsa.secret_key);
        service_node.register_mq_server(quic.get());

        auto http_client = std::make_shared<http::Client>(quic->loop);
        service_node.set_http_client(http_client);
        request_handler.set_http_client(http_client);

        oxenmq_server.init(
                &service_node,
                &request_handler,
                &rate_limiter,
                oxenmq::address{options.lux_rpc});

        quic->startup_endpoint();

        https_server.start();

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        oxenmq_server->add_timer(
                [&service_node] {
                    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + service_node.get_status_line()).c_str());
                },
                10s);
#endif

        // Log general stats at startup and again every hour
        log::info(logcat, "{}", service_node.get_status_line());
        oxenmq_server->add_timer(
                [&service_node] { log::info(logcat, "{}", service_node.get_status_line()); }, 1h);

        while (signalled.load() == 0)
            std::this_thread::sleep_for(100ms);

        log::warning(logcat, "Received signal {}; shutting down...", signalled.load());
        http_client.reset();
        service_node.shutdown();
        log::info(logcat, "Stopping https server");
        https_server.shutdown(true);
        log::info(logcat, "Stopping quic server");
        quic.reset();
        log::info(logcat, "Stopping omq server");
        oxenmq_server_ptr.reset();
        log::info(logcat, "Pars storage server shut down successfully");
    } catch (const std::exception& e) {
        std::cerr << "Exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown exception caught in main." << std::endl;
        return EXIT_FAILURE;
    }
}
