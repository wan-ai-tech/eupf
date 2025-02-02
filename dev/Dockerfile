FROM golang:1.22.4-bullseye

WORKDIR /app

# Install dependencies for ebpf compilation
RUN apt update \
    && apt install --no-install-recommends -y \
    clang \
    llvm \
    gcc-multilib \
    libbpf-dev \
    iproute2 \
    python3-pip \
    python3-dev \
    python3-venv \
    python3-pytest \
    python3-scapy \
    tcpreplay \
    && rm -rf /var/lib/apt/lists/*

RUN pip install \
    robotframework \
    robotframework-requests \
    robotframework-run-keyword-async \
    python-can \
    git+https://github.com/kade-ddnkv/robotframework-ScapyLibrary@master


RUN go install github.com/swaggo/swag/cmd/swag@v1.8.12 \
    && go install github.com/cortesi/modd/cmd/modd@latest

CMD [ "modd",  "-f",  "/app/dev/modd.conf" ]
