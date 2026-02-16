FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    nfs-common \
    rpcbind \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Debug \
    && cmake --build build -j$(nproc)

CMD ["ctest", "--test-dir", "build", "--output-on-failure"]
