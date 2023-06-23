# Using the same base golang image as geth
FROM golang:1.20-alpine as builder

RUN apk add --no-cache gcc musl-dev binutils-gold linux-headers git

# Get and cache deps
COPY go.mod /plugeth-statediff/
COPY go.sum /plugeth-statediff/
RUN cd /plugeth-statediff && go mod download

ADD . /plugeth-statediff
RUN cd /plugeth-statediff && \
    go build --tags linkgeth --buildmode=plugin --trimpath -o statediff.so ./main

FROM alpine:latest

COPY --from=builder /plugeth-statediff/statediff.so /usr/local/lib/
