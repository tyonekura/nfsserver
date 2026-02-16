# Integration Testing

## Single-Container Test (Loopback)

Quick smoke test running server and client in the same container:

```bash
docker build -t nfsd-test .
docker run --rm --privileged nfsd-test bash -c '
  mkdir -p /tmp/nfs_export && echo test > /tmp/nfs_export/hello.txt
  ./build/nfsd --export /tmp/nfs_export --port 2049 &
  sleep 1
  mkdir -p /mnt/nfs3 /mnt/nfs4
  mount -t nfs -o vers=3,proto=tcp,port=2049,nolock 127.0.0.1:/ /mnt/nfs3
  mount -t nfs4 -o vers=4.0,proto=tcp,port=2049 127.0.0.1:/ /mnt/nfs4
  cat /mnt/nfs3/hello.txt && cat /mnt/nfs4/hello.txt
  echo "=== All OK ==="
'
```

## Two-Container Test (Cross-Node)

Tests NFS across separate containers on a Docker network, simulating a real client/server deployment.

### Setup

```bash
# Build the image
docker build -t nfsd-test .

# Create a Docker network
docker network create nfs-test-net
```

### Start the Server

```bash
docker run -d --name nfs-server --network nfs-test-net \
  nfsd-test bash -c '
    mkdir -p /export/subdir
    echo "Hello from NFS server" > /export/hello.txt
    echo "Nested file" > /export/subdir/nested.txt
    dd if=/dev/urandom of=/export/testdata.bin bs=1024 count=100 2>/dev/null
    exec ./build/nfsd --export /export --port 2049
  '

# Verify server is running
sleep 2 && docker logs nfs-server
```

Expected output:
```
NFS server starting...
  Export: /export
  Port:   2049
RPC server listening on port 2049
```

(Portmapper warnings are expected if rpcbind is not running in the container.)

### Run the Client Tests

```bash
docker run --rm --name nfs-client --network nfs-test-net --privileged \
  nfsd-test bash -c '
    set -e

    echo "=== NFSv3 Mount Test ==="
    mkdir -p /mnt/nfs3
    mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=2049,nolock nfs-server:/ /mnt/nfs3
    echo "NFSv3 mount succeeded!"

    echo "--- Read ---"
    cat /mnt/nfs3/hello.txt
    cat /mnt/nfs3/subdir/nested.txt

    echo "--- Write ---"
    echo "Written from NFS client" > /mnt/nfs3/client-wrote.txt
    cat /mnt/nfs3/client-wrote.txt

    echo "--- Mkdir ---"
    mkdir /mnt/nfs3/newdir
    ls -la /mnt/nfs3/

    echo "--- Stat ---"
    stat /mnt/nfs3/hello.txt

    echo "--- Binary file ---"
    ls -l /mnt/nfs3/testdata.bin

    umount /mnt/nfs3
    echo "NFSv3 unmount succeeded!"

    echo ""
    echo "=== NFSv4 Mount Test ==="
    mkdir -p /mnt/nfs4
    mount -t nfs4 -o port=2049 nfs-server:/ /mnt/nfs4
    echo "NFSv4 mount succeeded!"

    echo "--- Read ---"
    cat /mnt/nfs4/hello.txt
    cat /mnt/nfs4/subdir/nested.txt

    echo "--- Write ---"
    echo "NFSv4 write test" > /mnt/nfs4/v4-wrote.txt
    cat /mnt/nfs4/v4-wrote.txt

    echo "--- List (should see files from v3 client too) ---"
    ls -la /mnt/nfs4/

    umount /mnt/nfs4
    echo "NFSv4 unmount succeeded!"

    echo ""
    echo "=== ALL TESTS PASSED ==="
  '
```

### Cleanup

```bash
docker rm -f nfs-server
docker network rm nfs-test-net
```

### Mount Options Reference

| Option | Purpose |
|--------|---------|
| `vers=3` / `nfs4` | Select NFS protocol version |
| `proto=tcp` | Use TCP transport (only transport supported) |
| `port=2049` | Server port (required since portmapper may not be available) |
| `mountport=2049` | MOUNT protocol port (v3 only; same port as NFS) |
| `nolock` | Disable NLM locking (NLM not yet implemented for v3) |

### What Gets Tested

- **NFSv3**: mount, readdir, read, write, mkdir, stat, nested lookup, unmount
- **NFSv4**: mount, readdir, read, write, nested lookup, unmount
- **Cross-version**: files written via v3 are visible via v4 and vice versa
- **Networking**: TCP connection between separate containers on a Docker bridge network

### Known Issues

- NFSv4 `ls -la` may show `.` duplicated — cosmetic READDIR issue
- `nolock` is required for NFSv3 until NLM (#30) is implemented
- Portmapper warnings on server startup are normal if rpcbind is not installed
