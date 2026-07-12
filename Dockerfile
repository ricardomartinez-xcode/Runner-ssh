FROM node:22-bookworm-slim AS build
WORKDIR /app

COPY package.json ./
RUN npm install --no-package-lock --ignore-scripts \
    && node -e "for (const packageName of ['fastify', 'jose', 'yaml', 'zod']) {require.resolve(packageName)}"

COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM 1password/op:2 AS onepassword

FROM node:22-bookworm-slim
ARG CLOUDFLARED_VERSION=2026.7.1
ARG CLOUDFLARED_SHA256=79f790b45e6a9152c6cf63f60f4901e3d8a029f7f4be1345a24cd2373aba8e7d
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl dumb-init git openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64.deb" \
    && echo "${CLOUDFLARED_SHA256}  /tmp/cloudflared.deb" | sha256sum -c - \
    && dpkg -i /tmp/cloudflared.deb \
    && rm -f /tmp/cloudflared.deb
RUN mkdir -p -m 755 /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*
COPY --from=onepassword /usr/local/bin/op /usr/local/bin/op
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY config ./config
COPY package.json ./
RUN useradd --create-home --shell /bin/bash runner \
    && install -d -m 0700 -o runner -g runner /home/runner/.ssh \
    && mkdir -p /var/data \
    && chown -R runner:runner /app /var/data
USER runner
ENV NODE_ENV=production PORT=10000 HOST=0.0.0.0 DATA_DIR=/var/data RUNNER_CONFIG_PATH=/app/config/runner.yaml
EXPOSE 10000
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
