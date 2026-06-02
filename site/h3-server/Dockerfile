FROM node:22-alpine
RUN apk add --no-cache bash curl
RUN addgroup -S coquic && adduser -S -G coquic coquic
COPY zig-out/bin/h3-server /opt/coquic-demo/current/h3-server
COPY zig-out/demo-app /opt/coquic-demo/current/app
COPY site/deploy/run-demo.sh /opt/coquic-demo/current/run-demo.sh
RUN chown -R coquic:coquic /opt/coquic-demo
ENV COQUIC_DEMO_CERTIFICATE_CHAIN=/run/certs/cert.pem
ENV COQUIC_DEMO_PRIVATE_KEY=/run/certs/key.pem
ENV COQUIC_DEMO_PORT=4433
ENV COQUIC_DEMO_BOOTSTRAP_PORT=4433
USER coquic
ENTRYPOINT ["/opt/coquic-demo/current/run-demo.sh"]
