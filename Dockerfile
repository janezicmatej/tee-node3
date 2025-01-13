# Build stage  
FROM golang:1.22-alpine AS builder  

# Install git and certificates (needed for private repos and some dependencies)  
RUN apk add --no-cache git ca-certificates tzdata  

# Set working directory  
WORKDIR /app  

# Copy go mod and sum files  
COPY go.mod go.sum ./  

# Download dependencies  
RUN go mod download  

# Copy the source code  
COPY . .  

# Build the application  
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server cmd/server/main.go

# ---------------------------- --------------------------------------------

# Final stage  
FROM alpine:latest

# Import certificates from builder  
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/  

# Copy binary from builder  
COPY --from=builder /app/server /app/server  

# Set environment variables  
ENV TZ=UTC  

# Expose port (adjust as needed)  
EXPOSE 80
EXPOSE 443/tcp
EXPOSE 81/udp
EXPOSE 50051  

# Run the application  
CMD ["/app/server"]