FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    iproute2 \
    iputils-ping \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt /app/CMakeLists.txt
COPY src /app/src

RUN cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /app/build -j

RUN cp /app/build/netstack /app/netstack

CMD ["/app/netstack", "--tap", "tap0", "--ip", "10.0.0.2/24", "--mac", "02:00:00:00:00:02"]
