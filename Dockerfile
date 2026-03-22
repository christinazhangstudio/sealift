# build stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux \
go build -o sealift .

# run stage
FROM alpine:latest

# add time zones
ADD https://github.com/golang/go/raw/master/lib/time/zoneinfo.zip /zoneinfo.zip
ENV ZONEINFO /zoneinfo.zip

WORKDIR /root/
COPY --from=builder /app/sealift .
COPY --from=builder /app/docs ./docs
EXPOSE 443
CMD ["./sealift"]