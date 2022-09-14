FROM debian:buster
RUN apt update && \
    apt install -y libssl-dev build-essential curl git

# Install cmake
RUN curl -LO -s https://github.com/Kitware/CMake/releases/download/v3.24.2/cmake-3.24.2-linux-x86_64.sh \
  && chmod +x cmake-3.24.2-linux-x86_64.sh \
  && ./cmake-3.24.2-linux-x86_64.sh --skip-license \
  && rm cmake-3.24.2-linux-x86_64.sh 

RUN cd /tmp \
  && curl -LO https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Bionic/cloudhsm-dyn_latest_u18.04_amd64.deb \
  && apt install -y ./cloudhsm-dyn_latest_u18.04_amd64.deb \
  && rm ./cloudhsm-dyn_latest_u18.04_amd64.deb

WORKDIR /app

COPY . .

RUN mkdir -p bin && cd bin && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .

ENTRYPOINT ["./scripts/start_server.sh"]
