#pragma once

#include <cstdint>

// RFC 1833 - Portmapper v2 (program 100000) client
// Registers/unregisters RPC programs with the local rpcbind daemon on port 111.

constexpr uint32_t PMAP_PROGRAM = 100000;
constexpr uint32_t PMAP_VERSION = 2;
constexpr uint32_t PMAPPROC_SET   = 1;
constexpr uint32_t PMAPPROC_UNSET = 2;
constexpr uint32_t IPPROTO_TCP_PMAP = 6;

// Register a single RPC program/version with portmapper.
// Returns true on success, false if portmapper unreachable (non-fatal).
bool pmap_register(uint32_t program, uint32_t version, uint16_t port);

// Unregister a single RPC program/version from portmapper.
bool pmap_unregister(uint32_t program, uint32_t version);

// Register all NFS server programs (NFS v3, NFS v4, MOUNT v3).
void pmap_register_all(uint16_t port);

// Unregister all NFS server programs.
void pmap_unregister_all();
