#pragma once

#include "rpc/rpc_server.h"
#include "vfs/vfs.h"
#include <string>
#include <vector>

class MountServer {
public:
    MountServer(Vfs& vfs, const std::vector<std::string>& exports);

    // Returns RPC handlers to register with RpcServer.
    RpcProgramHandlers get_handlers();

private:
    void proc_null(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_mnt(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_dump(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_umnt(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);
    void proc_export(const RpcCallHeader& call, XdrDecoder& args, XdrEncoder& reply);

    Vfs& vfs_;
    std::vector<std::string> exports_;
};
