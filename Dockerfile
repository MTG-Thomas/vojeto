FROM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN scripts/prepare-nebula-patch.sh /nebula-patched /src/vojeto-patched.mod
ENV GOFLAGS=-modfile=/src/vojeto-patched.mod
RUN cd /nebula-patched && GOFLAGS= go test -race -run '^TestPacketCacheConcurrentCountAndTransfer$' -count=100 -timeout=2m .
RUN go test -race -run "^TestVojetoTailProbe" -count=100 gvisor.dev/gvisor/pkg/tcpip/transport/tcp
RUN go test -race -timeout=4m ./...
RUN go vet ./...
RUN go list -deps ./... > /tmp/deps && ! grep -q '^golang.org/x/crypto/openpgp' /tmp/deps
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -o /vojeto ./cmd/vojeto
RUN CGO_ENABLED=0 go test -c -o /netstack.test ./internal/network/netstack
FROM scratch AS proof
COPY --from=build /netstack.test /netstack.test
USER 65532:65532
ENTRYPOINT ["/netstack.test"]
FROM proof AS measurements
COPY --from=build /vojeto /vojeto
ENV VOJETO_BINARY=/vojeto VOJETO_PROFILE=1 GOMEMLIMIT=96MiB
FROM scratch AS runtime
# Leave RSS headroom for a 128 MiB container; Go memory limits are soft.
ENV GOMEMLIMIT=96MiB
COPY --from=build /vojeto /vojeto
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY NEBULA_LICENSE /licenses/NEBULA_LICENSE
COPY GVISOR_LICENSE /licenses/GVISOR_LICENSE
COPY LICENSE /licenses/VOJETO_LICENSE
COPY THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
USER 65532:65532
ENTRYPOINT ["/vojeto"]
