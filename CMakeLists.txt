cmake_minimum_required(VERSION 3.16)
project(nfsd VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(nfs_lib STATIC
    src/xdr/xdr_codec.cpp
    src/rpc/rpc_server.cpp
    src/vfs/vfs.cpp
    src/vfs/local_fs.cpp
    src/mount/mount_server.cpp
    src/nfs/nfs_server.cpp
    src/nfs/nfs_procedures.cpp
)
target_include_directories(nfs_lib PUBLIC src)
target_compile_options(nfs_lib PRIVATE -Wall -Wextra -Wpedantic)

add_executable(nfsd src/main.cpp)
target_link_libraries(nfsd PRIVATE nfs_lib pthread)

enable_testing()
add_subdirectory(tests)
