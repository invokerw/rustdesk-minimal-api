# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/rustdesk-minimal-api .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/rustdesk-minimal-api /usr/local/bin/rustdesk-minimal-api
COPY --chown=nonroot:nonroot data/.keep /data/.keep

WORKDIR /data
VOLUME ["/data"]
EXPOSE 21114

ENV RUSTDESK_API_LISTEN=0.0.0.0:21114 \
    RUSTDESK_API_DATA=/data/state.json \
    RUSTDESK_API_ENABLE_INVENTORY=false

ENTRYPOINT ["/usr/local/bin/rustdesk-minimal-api"]
