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
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl dumb-init git openssh-client sshpass \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p -m 755 /etc/apt/keyrings /usr/share/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg \
    && chmod go+r /usr/share/keyrings/cloudflare-main.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends cloudflared gh \
    && cloudflared --version \
    && rm -rf /var/lib/apt/lists/*
COPY --from=onepassword /usr/local/bin/op /usr/local/bin/op
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY config ./config
COPY package.json ./
RUN useradd --create-home --shell /usr/sbin/nologin runner \
    && mkdir -p /var/data \
    && chown -R runner:runner /app /var/data
USER runner
ENV NODE_ENV=production PORT=10000 HOST=0.0.0.0 DATA_DIR=/var/data RUNNER_CONFIG_PATH=/app/config/runner.yaml
EXPOSE 10000
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
