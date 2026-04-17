FROM alpine:3.21
COPY zig-out/bin/h3-server /usr/local/bin/h3-server
COPY docker/h3-server/www /app/www
ENTRYPOINT ["/usr/local/bin/h3-server"]
CMD ["--host","0.0.0.0","--port","4433","--bootstrap-port","4433","--document-root","/app/www","--certificate-chain","/run/certs/cert.pem","--private-key","/run/certs/key.pem"]
