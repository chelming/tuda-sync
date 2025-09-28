# Stage 1: Builder
# Use a minimal Go image for the build stage
FROM golang:1.25-alpine AS builder

# Install UPX for binary compression
RUN apk add --no-cache upx

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Compile the static binary with extreme optimizations for minimal size
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
    -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -tags netgo,osusergo \
    -o /tuda-sync \
    && upx --best --lzma /tuda-sync

# ------------------------------------------------------------------------

# Stage 2: Final Image (Using the absolute minimal possible base)
FROM scratch

# Copy the static binary from the builder stage
COPY --from=builder /tuda-sync /usr/local/bin/tuda-sync

# Copy only the CA certificates bundle
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy timezone data (only if your app needs it)
# COPY --from=alpine:latest /usr/share/zoneinfo /usr/share/zoneinfo

# Create non-root user (in a scratch container we need to do this differently)
# since there's no useradd command, we manually set permissions and user in entrypoint
# The binary is already set up to run as non-root

# Set the entrypoint to our binary
ENTRYPOINT ["/usr/local/bin/tuda-sync"]
# Default command if no arguments are provided
CMD []

# Reverting to an Alpine-based final image, but simplified, as it's the safest bet 
# when mixing Go static compilation with external HTTPS CA dependencies.

# Stage 2: Final Image (Simplified Alpine - Cleaner than previous)
FROM alpine:latest
RUN apk --no-cache add ca-certificates

# Copy the built binary
COPY --from=builder /tuda-sync /usr/local/bin/tuda-sync

# Add health check
HEALTHCHECK --interval=60s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8080/health || exit 1

# The binary must run as root to access /var/run/docker.sock, 
# but setting the user explicitly is good practice if using an entrypoint.

# Add container metadata
ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="tuda-sync" \
      org.opencontainers.image.description="Traefik/Unbound/Docker/Alias Synchronization" \
      org.opencontainers.image.url="https://github.com/chelming/tuda-sync" \
      org.opencontainers.image.source="https://github.com/chelming/tuda-sync" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="Non-Commercial"

# Set the entrypoint to the compiled binary
ENTRYPOINT ["/usr/local/bin/tuda-sync"]
