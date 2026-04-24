# Reproducible Builds

This project produces reproducible Docker images. Given the same source code,
builds produce bit-for-bit identical image layers regardless of when or where
they are built.

## How it works

- `SOURCE_DATE_EPOCH` is set to the commit timestamp and passed as a build arg
  to clamp all timestamps
- Go binary is built with `-trimpath -ldflags="-buildid= -s -w"` and
  `-buildvcs=false` to strip non-deterministic metadata; `CGO_ENABLED=1` with
  `-linkmode=external -extldflags=-static` plus the `netgo,osusergo` build
  tags produces a fully static binary that links the native C libsecp256k1
  from go-ethereum. The cgo toolchain (`gcc`, `libc6-dev`) is installed from
  the same pinned Debian snapshot as the rest of the packages, so link-time
  libc variance is eliminated
- Base image digest is pinned in the Dockerfile
- Debian package versions are pinned via apt's native snapshot support
  (Debian 13+): `Snapshot: true` in the sources file plus
  `apt-get install --snapshot <SOURCE_DATE_EPOCH>` redirects every fetch to
  [snapshot.debian.org](https://snapshot.debian.org) at the exact instant of
  the commit, so the same `SOURCE_DATE_EPOCH` always yields the same package
  bytes. Adapted from
  [reproducible-containers/repro-sources-list.sh](https://github.com/reproducible-containers/repro-sources-list.sh/blob/master/alternative/Dockerfile.debian-13)
- CI uses BuildKit's [`rewrite-timestamp=true`](https://github.com/moby/buildkit/pull/4057)
  exporter option to normalize layer timestamps

## Verifying a remote image

The default Docker builder does not properly support `rewrite-timestamp`
([moby/buildkit#4230](https://github.com/moby/buildkit/issues/4230)). You need
a BuildKit builder using the `docker-container` driver.

Create the builder (one-time setup):

```sh
docker buildx create \
  --driver=docker-container \
  --name=moby-buildkit \
  --driver-opt image=moby/buildkit \
  --driver-opt network=host \
  --bootstrap
```

Clone the repository, checkout the tag you want to verify, build locally and
compare the image config digest against the registry image.

The commands below use [`jq`](https://jqlang.org) to extract digests from JSON.
If you prefer not to install it, drop the `| jq ...` pipes and read the
`.config.digest` field out of the raw manifest JSON by hand.

```sh
git clone https://github.com/flare-foundation/tee-node.git
cd tee-node

TAG=$(git describe --tags --abbrev=0)
git checkout "$TAG"

# run an ephemeral local registry so the locally-built image and the published
# image can be inspected with the exact same `docker buildx imagetools` command,
# avoiding `docker inspect`'s backend-dependent `.Id` behavior
# (the `moby-buildkit` builder needs `--driver-opt network=host` at creation
# time to be able to reach `localhost:5050` from inside its container)
docker run -d --rm --name verify-registry -p 5050:5000 registry:2

docker buildx build \
  --builder moby-buildkit \
  --platform linux/amd64 \
  --no-cache \
  --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  --output "type=image,name=localhost:5050/tee-node:verify,rewrite-timestamp=true,push=true,registry.insecure=true" \
  -f Dockerfile .

# both published and locally-pushed images are multi-platform OCI indexes, so
# we resolve: index → linux/amd64 manifest → config digest (two lookups each)
resolve_config() {
  local img=$1 manifest
  manifest=$(docker buildx imagetools inspect --raw "$img" \
    | jq -r '.manifests[]
        | select(.platform.os=="linux" and .platform.architecture=="amd64")
        | .digest')
  docker buildx imagetools inspect --raw "$img@$manifest" \
    | jq -r '.config.digest'
}

resolve_config localhost:5050/tee-node:verify
resolve_config ghcr.io/flare-foundation/tee-node:"$TAG"

docker stop verify-registry
```

Or, if [`crane`](https://github.com/google/go-containerregistry) is available,
the two-step resolution collapses into one command per image:

```sh
crane manifest --platform linux/amd64 \
  localhost:5050/tee-node:verify | jq -r '.config.digest'
crane manifest --platform linux/amd64 \
  ghcr.io/flare-foundation/tee-node:"$TAG" | jq -r '.config.digest'
```

Both digests should be identical.

### Why the config digest, and why not `docker inspect`

The config digest is the sha256 of the OCI image config JSON — it deterministically
covers the rootfs layer digests plus all config fields (env, entrypoint, labels,
etc.) and is what reproducibility actually needs to match.

`docker inspect --format='{{.Id}}'` is avoided because its meaning depends on
the host's storage backend: it returns the config digest with the classic graph
driver store and the manifest digest with the containerd image store. The
manifest digest also covers signatures and platform metadata, so two hosts that
produced byte-identical configs can still report different `.Id` values.

`imagetools inspect --raw` works against the registry's standard manifest
format rather than the daemon's internal view, so it yields the config digest
regardless of Docker's storage backend — which is why the build is pushed to a
local registry instead of `--load`ed.

## Upstream references

- [moby/buildkit#3180](https://github.com/moby/buildkit/issues/3180) -
  `rewrite-timestamp` only clamps timestamps *down* to `SOURCE_DATE_EPOCH`,
  older timestamps are left unchanged. The Dockerfile works around this with
  an explicit `find + touch` to normalize all timestamps before COPY.
- [moby/buildkit#4057](https://github.com/moby/buildkit/pull/4057) - PR that
  added `rewrite-timestamp` support to BuildKit exporters
- [moby/buildkit#4230](https://github.com/moby/buildkit/issues/4230) - open
  issue tracking `rewrite-timestamp` incompatibility with the default Docker
  builder and `--load` (`unpack` conflict)
