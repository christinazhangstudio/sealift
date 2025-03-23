# build stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
go build -o ebay-notifications .

# run stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/ebay-notifications .
COPY server.crt .
COPY server.key .
EXPOSE 443
CMD ["./ebay-notifications"]