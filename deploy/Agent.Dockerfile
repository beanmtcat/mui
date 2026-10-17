# Build-only recipe: build-agent.sh exports Linux binaries with --output.
# Agents are installed on target hosts as systemd services, not containers.
FROM golang:1.25.1-bookworm AS agent-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/mui-agent ./cmd/agent

FROM golang:1.25.1-bookworm AS core-builder
ARG SING_BOX_VERSION=v1.14.2
# Optional: pin the exact upstream commit for the tag above. A tag alone can
# be moved; a commit cannot. Leave empty to build from the tag as before.
ARG SING_BOX_COMMIT=""
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${SING_BOX_VERSION}" https://github.com/SagerNet/sing-box.git /src/sing-box && \
    if [ -n "${SING_BOX_COMMIT}" ]; then git -C /src/sing-box fetch --depth 1 origin "${SING_BOX_COMMIT}" && git -C /src/sing-box checkout "${SING_BOX_COMMIT}"; fi && \
    git -C /src/sing-box rev-parse HEAD
WORKDIR /src/sing-box
# The default tag list is comma separated. with_naive_outbound needs cgo, which a static build does not have.
# Without constant.Version the binary reports "version unknown" and the agent rejects it.
RUN TAGS="$(tr ',' '\n' < release/DEFAULT_BUILD_TAGS | grep -Ev '^(with_naive_outbound|with_clash_api|with_v2ray_api)$' | paste -sd, -),with_v2ray_api,with_clash_api" && \
    GOFLAGS=-trimpath CGO_ENABLED=0 go build -tags "$TAGS" -ldflags "$(cat release/LDFLAGS) -X github.com/sagernet/sing-box/constant.Version=${SING_BOX_VERSION#v}" -o /out/sing-box ./cmd/sing-box

FROM scratch
COPY --from=agent-builder /out/mui-agent /mui-agent
COPY --from=core-builder /out/sing-box /sing-box
