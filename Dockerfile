FROM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN scripts/prepare-nebula-patch.sh /nebula-patched /src/vojeto-patched.mod
ENV GOFLAGS=-modfile=/src/vojeto-patched.mod
RUN go test -race ./...
RUN CGO_ENABLED=0 go build -trimpath -o /vojeto ./cmd/vojeto
RUN CGO_ENABLED=0 go test -c -o /netstack.test ./internal/network/netstack
FROM scratch AS proof
COPY --from=build /netstack.test /netstack.test
USER 65532:65532
ENTRYPOINT ["/netstack.test"]
FROM scratch AS runtime
COPY --from=build /vojeto /vojeto
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY NEBULA_LICENSE /licenses/NEBULA_LICENSE
COPY LICENSE /licenses/VOJETO_LICENSE
USER 65532:65532
ENTRYPOINT ["/vojeto"]
