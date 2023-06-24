# Using the same base golang image as geth
FROM golang:1.20-alpine as builder

RUN apk add --no-cache gcc musl-dev binutils-gold linux-headers git

WORKDIR /plugeth-statediff/

# Get and cache deps
COPY go.mod .
COPY go.sum .
RUN go mod download

ADD . .
RUN go build --tags linkgeth --buildmode=plugin --trimpath -o statediff.so ./main

FROM alpine:latest

COPY --from=builder /plugeth-statediff/statediff.so /usr/local/lib/
