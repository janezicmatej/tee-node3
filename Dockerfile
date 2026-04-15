FROM golang:1.25.1-trixie@sha256:ff83f3762390c2cccb53618ccc18af23e556aff9b1db4428637e9f63287c8171 AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /app

# pin apt sources to SOURCE_DATE_EPOCH snapshot for reproducibility
COPY --chmod=755 --chown=0:0 repro-sources-list.sh .
RUN ./repro-sources-list.sh

RUN apt-get update \
 && apt-get -y install --no-install-recommends \
      git=1:2.* \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --chmod=644 --chown=0:0 go.mod go.sum ./
RUN go mod download
RUN go mod verify

COPY --chmod=644 --chown=0:0 . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS="-buildvcs=false" \
    go build -trimpath -ldflags="-buildid= -s -w" -o /app/server cmd/main.go

# NOTE:(@janezicmatej) rewrite-timestamp only clamps down (moby/buildkit#3180)
RUN find /app -exec touch -h -d @${SOURCE_DATE_EPOCH} {} +

FROM scratch

COPY --chmod=644 --chown=65532:65532 --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=755 --chown=65532:65532 --from=builder /app/server /app/server
COPY --chmod=644 --chown=65532:65532 --from=builder /app/assets/google_confidential_space_root.crt /app/assets/google_confidential_space_root.crt

LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL,PROXY_URL,INITIAL_OWNER,EXTENSION_ID"

EXPOSE 5500

WORKDIR /app
USER 65532:65532
ENV MODE=0
CMD ["./server"]
