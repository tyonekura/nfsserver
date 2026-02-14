#include "rpc/rpc_server.h"
#include "rpc/rpc_types.h"
#include "mount/mount_server.h"
#include "nfs/nfs_server.h"
#include "vfs/local_fs.h"

#include <csignal>
#include <iostream>
#include <string>
#include <vector>

static RpcServer* g_server = nullptr;

static void signal_handler(int) {
    if (g_server) g_server->stop();
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " --export <path> [--port <port>]\n"
              << "  --export <path>   Directory to export via NFS (required)\n"
              << "  --port <port>     TCP port to listen on (default: 2049)\n";
}

int main(int argc, char* argv[]) {
    std::string export_path;
    uint16_t port = 2049;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--export" && i + 1 < argc) {
            export_path = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
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
        std::vector<std::string> exports = {"/"};

        MountServer mount_srv(vfs, exports);
        NfsServer nfs_srv(vfs);

        RpcServer rpc;
        g_server = &rpc;

        rpc.register_program(MOUNT_PROGRAM, MOUNT_V3, mount_srv.get_handlers());
        rpc.register_program(NFS_PROGRAM, NFS_V3, nfs_srv.get_handlers());

        std::cout << "NFS server starting...\n"
                  << "  Export: " << export_path << "\n"
                  << "  Port:   " << port << "\n";

        rpc.start(port);

        // Wait for signal.
        pause();

    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
