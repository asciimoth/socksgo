FROM golang:1.25.5-bookworm

ARG GOST_VERSION=3.2.6
ARG TARGETARCH

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
        apt-get install --yes --no-install-recommends \
        ca-certificates \
        curl \
        tor \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) \
            gost_sha256="b39037b0380ea001fb3c0c28441c2e10bfc694f90682739a65b53e55dce5238b" \
            ;; \
        arm64) \
            gost_sha256="f674c8f4a033dc1dfd4f0d5e9602fbe5b0d0f81307bf3794f44b5b5d6d622eae" \
            ;; \
        *) \
            echo "unsupported container architecture: ${TARGETARCH}" >&2 \
            exit 1 \
            ;; \
    esac \
    && archive="gost_${GOST_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && curl --fail --location --show-error --silent \
        --output "/tmp/${archive}" \
        "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/${archive}" \
    && echo "${gost_sha256}  /tmp/${archive}" | sha256sum --check - \
    && tar --extract --gzip --file "/tmp/${archive}" \
        --directory /usr/local/bin gost \
    && rm "/tmp/${archive}"

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY test/e2e/entrypoint.sh /usr/local/bin/socksgo-e2e-entrypoint
COPY test/e2e/torrc /usr/local/etc/socksgo-torrc

ENTRYPOINT ["/usr/local/bin/socksgo-e2e-entrypoint"]
CMD ["go", "test", "./...", "-tags=compattest testhooks", "-count=1"]
