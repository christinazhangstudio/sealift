# build stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
go build -o sealift-webhook .

# run stage
FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/sealift-webhook .
COPY cert/sealift.crt cert/
COPY cert/sealift.key cert/
EXPOSE 443
CMD ["./sealift-webhook"]