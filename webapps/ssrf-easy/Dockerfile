FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY templates/ ./templates/
RUN CGO_ENABLED=0 GOOS=linux go build -o linkpeek .

FROM alpine:3.19
WORKDIR /app
RUN mkdir -p /data
COPY --from=builder /app/linkpeek .
COPY --from=builder /app/templates/ ./templates/

# SCORE_TOKEN must be set at runtime — score routes are disabled if unset
ENV SCORE_TOKEN=""
ENV DATA_DIR=/data
EXPOSE 5000
CMD ["./linkpeek"]
