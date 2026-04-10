# Build stage  
FROM golang:1.25.1-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Install git and certificates (needed for private repos and some dependencies)  
RUN apk add --no-cache git ca-certificates tzdata  

# Set working directory  
WORKDIR /app  

# Copy go mod and sum files
COPY --chmod=644 go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY --chmod=644 . .

# normalize timestamps so COPY --from=builder is deterministic
# NOTE:(@janezicmatej) rewrite-timestamp only clamps down (moby/buildkit#3180)
RUN find /app -exec touch -h -d @${SOURCE_DATE_EPOCH} {} +

# Build the application  
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-buildid= -s -w" -o /app/server cmd/main.go

# ------------------------------------------------------------------------

# Final stage  
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Import certificates from builder  
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/  

# Copy binary from builder  
COPY --from=builder /app/server /app/server  
COPY --from=builder /app/assets/google_confidential_space_root.crt /app/assets/google_confidential_space_root.crt

# Set environment variables  
ENV TZ=UTC

LABEL "tee.launch_policy.allow_env_override"="LOG_LEVEL,PROXY_URL,INITIAL_OWNER,EXTENSION_ID"

# Expose port (adjust as needed)  
EXPOSE 5500

# Run the application
WORKDIR /app  
ENV MODE=0
CMD ["./server"]
