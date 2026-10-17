FROM golang:1.25.1-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 go build -trimpath -o /out/mui-server ./cmd/server

# Debian slim has no x.y.z patch tag; its tags are date-based
# (bookworm-YYYYMMDD-slim). Pin the digest at build time if reproducibility
# must survive a base-image rebuild, e.g. --build-arg BASE_DIGEST=...
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --home /app mui
WORKDIR /app
COPY --from=go-builder /out/mui-server ./mui-server
RUN mkdir /app/data && chown mui:mui /app/data
USER mui
EXPOSE 8080
CMD ["./mui-server"]
