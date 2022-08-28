FROM debian:buster
RUN apt update && \
    apt install -y libssl-dev cmake build-essential curl

RUN cd /tmp \
  && curl https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Bionic/cloudhsm-dyn_latest_u18.04_amd64.deb --output ./cloudhsm-dyn_latest_u18.04_amd64.deb \
  && apt install -y ./cloudhsm-dyn_latest_u18.04_amd64.deb \
  && rm ./cloudhsm-dyn_latest_u18.04_amd64.deb

WORKDIR /app

COPY . .

RUN mkdir -p bin && cd bin && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build .

ENTRYPOINT ["./scripts/start_server.sh"]
