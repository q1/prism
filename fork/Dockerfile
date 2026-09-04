FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata bash \
    && addgroup -g 1000 cliproxy \
    && adduser -D -u 1000 -G cliproxy cliproxy
ARG TARGETOS
ARG TARGETARCH
COPY --chmod=755 ${TARGETOS}/${TARGETARCH}/cli-proxy-api /CLIProxyAPI/CLIProxyAPI
WORKDIR /CLIProxyAPI
USER 1000:1000
CMD ["/CLIProxyAPI/CLIProxyAPI", "-config", "/CLIProxyAPI/config/config.yaml"]
