// NFS server entry point.
// MOUNT v3, NFS v3, and NFS v4 share a single RPC server on one TCP port.
// Optionally registers with portmapper/rpcbind on port 111.

#include "rpc/rpc_server.h"
#include "rpc/rpc_types.h"
#include "rpc/portmapper.h"
#include "mount/mount_server.h"
#include "nfs/nfs_server.h"
#include "nfs4/nfs4_server.h"
#include "nlm/nlm_server.h"
#include "nlm/nlm_types.h"
#include "vfs/local_fs.h"

#include <csignal>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

static volatile sig_atomic_t g_shutdown = 0;

static void signal_handler(int) {
    g_shutdown = 1;
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --export <path> [--port <port>] [--tls-cert <pem> --tls-key <pem>]\n"
              << "  --export <path>     Directory to export via NFS (required)\n"
              << "  --port <port>       TCP port to listen on (default: 2049)\n"
              << "  --tls-cert <path>   TLS certificate file (PEM)\n"
              << "  --tls-key <path>    TLS private key file (PEM, unencrypted)\n";
}

int main(int argc, char* argv[]) {
    std::string export_path;
    std::string tls_cert, tls_key;
    uint16_t port = 2049;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--export" && i + 1 < argc) {
            export_path = argv[++i];
        } else if (arg == "--tls-cert" && i + 1 < argc) {
            tls_cert = argv[++i];
        } else if (arg == "--tls-key" && i + 1 < argc) {
            tls_key = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            int p = std::stoi(argv[++i]);
            if (p < 1 || p > 65535) {
                std::cerr << "Error: port must be 1-65535\n";
                return 1;
            }
            port = static_cast<uint16_t>(p);
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (export_path.empty()) {
        std::cerr << "Error: --export is required\n";
        print_usage(argv[0]);
        return 1;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        LocalFs vfs(export_path);
        std::vector<std::string> exports = {export_path};

        MountServer mount_srv(vfs, exports);
        NfsServer nfs_srv(vfs);
        Nfs4Server nfs4_srv(vfs, export_path);
        NlmServer nlm_srv(nfs4_srv.lock_table(), nfs4_srv.lock_mutex());

        RpcServer rpc;

        // RFC 9289 — Optional TLS support
        if (!tls_cert.empty() && !tls_key.empty()) {
            auto tls_ctx = std::make_unique<RpcTlsContext>(tls_cert, tls_key);
            if (tls_ctx->valid()) {
                rpc.set_tls_context(std::move(tls_ctx));
                std::cout << "  TLS:    enabled (cert=" << tls_cert << ")\n";
            } else {
                std::cerr << "  Warning: TLS context invalid, continuing without TLS\n";
            }
        }

        rpc.register_program(MOUNT_PROGRAM, MOUNT_V3, mount_srv.get_handlers());
        rpc.register_program(NFS_PROGRAM, NFS_V3, nfs_srv.get_handlers());
        rpc.register_program(NFS_PROGRAM, NFS_V4, nfs4_srv.get_handlers());
        rpc.register_program(NLM_PROGRAM, NLM_V4, nlm_srv.get_handlers());

        std::cout << "NFS server starting...\n"
                  << "  Export: " << export_path << "\n"
                  << "  Port:   " << port << "\n";

        rpc.start(port);
        pmap_register_all(port);

        // Wait for shutdown signal (async-signal-safe polling)
        while (!g_shutdown) {
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, nullptr);
        }

        pmap_unregister_all();
        rpc.stop();

    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
