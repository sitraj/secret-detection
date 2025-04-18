# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o detector ./cmd/detector

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/detector .

# Copy templates and swagger files
COPY templates ./templates
COPY swagger.yaml .

# Expose port
EXPOSE 8080

# Run the application
CMD ["./detector"] 