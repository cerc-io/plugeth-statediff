# Using image with same alpine as plugeth,
# but go 1.21 to evade https://github.com/Consensys/gnark-crypto/issues/468
FROM golang:1.21-alpine as builder

RUN apk add --no-cache gcc musl-dev binutils-gold linux-headers git

# Configure creds for gitea
ARG GIT_VDBTO_TOKEN

# Get and cache deps
WORKDIR /plugeth-statediff
COPY go.mod go.sum ./
RUN if [ -n "$GIT_VDBTO_TOKEN" ]; then git config --global url."https://$GIT_VDBTO_TOKEN:@git.vdb.to/".insteadOf "https://git.vdb.to/"; fi && \
    go mod download && \
    rm -f ~/.gitconfig

COPY . .
RUN go build --tags linkgeth --buildmode=plugin --trimpath -o statediff.so ./main

FROM alpine:3.18

COPY --from=builder /plugeth-statediff/statediff.so /usr/local/lib/
