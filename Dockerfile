# Static, CGO-free binary on distroless static, running as nonroot.
#
#   docker build --platform linux/amd64 --build-arg VERSION=$(git rev-parse --short=12 HEAD) -t email-mcp .
#
# Base images are pinned by tag and multi-arch index digest; update both
# together (docs/DECISIONS.md D36). The build stage runs on the build host's
# platform and cross-compiles, so building on arm64 needs no emulation.

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly

# Modules first: this layer is reused until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
	GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -buildvcs=false -ldflags="-X main.version=${VERSION}" -o /out/email-mcp ./cmd/email-mcp

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
COPY --from=build /out/email-mcp /email-mcp
# nonroot (65532:65532), numeric so runtimes can verify it is not root.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/email-mcp"]
