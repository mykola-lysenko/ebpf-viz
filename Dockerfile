# eBPF Visualizer — standalone Docker image
# Builds bpftool from source and bundles the Node.js app.
#
# Build:  docker build -t ebpf-viz .
# Run:    docker run --privileged --pid=host --network=host \
#           -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
#           -v /sys/kernel/debug:/sys/kernel/debug:ro \
#           -p 3000:3000 ebpf-viz
#
# NOTE: --privileged is required so bpftool can access /sys/fs/bpf and
#       the BPF syscall. Alternatively, use --cap-add=SYS_ADMIN.

FROM node:22-bookworm-slim AS base
WORKDIR /app

# ── Stage 1: build bpftool from source ──────────────────────────────────────
FROM base AS bpftool-builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    git build-essential libelf-dev zlib1g-dev libcap-dev \
    libzstd-dev pkg-config binutils-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/libbpf/bpftool.git /bpftool \
  && cd /bpftool && git submodule update --init \
  && cd src && make -j$(nproc) \
  && cp bpftool /usr/local/bin/bpftool

# ── Stage 2: install Node dependencies ──────────────────────────────────────
FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile

# ── Stage 3: build the app ───────────────────────────────────────────────────
FROM deps AS builder
COPY . .
RUN pnpm build

# ── Stage 4: production image ────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runner
WORKDIR /app

# Runtime deps for bpftool
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libelf1 libzstd1 libcap2 binutils \
  && rm -rf /var/lib/apt/lists/*

COPY --from=bpftool-builder /usr/local/bin/bpftool /usr/local/sbin/bpftool
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Allow the node user to run bpftool without a password
RUN echo "node ALL=(ALL) NOPASSWD: /usr/local/sbin/bpftool" \
    > /etc/sudoers.d/ebpf-viz \
  && chmod 440 /etc/sudoers.d/ebpf-viz \
  && apt-get install -y --no-install-recommends sudo \
  && rm -rf /var/lib/apt/lists/*

USER node
EXPOSE 3000
ENV NODE_ENV=production PORT=3000

CMD ["node", "dist/index.js"]
