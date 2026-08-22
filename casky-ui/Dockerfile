# casky-ui — self-hosted Next.js UI for browsing Casky Box investigations,
# findings, remediation status, and reports out of the casky_db Postgres schema.
#
# Multi-stage build using Next's `standalone` output (next.config.ts) so the
# final runtime image ships only the traced node_modules subset, not a full
# `npm install`. Binds 127.0.0.1-only by default — see docker-compose.yml's
# `ui` service port mapping, not this Dockerfile (a container has no concept
# of "localhost-only" on its own; the host-side bind lives in compose).

FROM node:22-alpine AS deps
WORKDIR /app
# @casky/ui-kit is a `file:./vendor/ui-kit` dependency (see
# vendor/ui-kit/VENDORED.md) — vendor/ must be present before `npm ci`
# resolves it.
COPY package.json package-lock.json ./
COPY vendor/ ./vendor/
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/vendor ./vendor
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 caskyui

# Next's standalone output already includes only the node_modules subset it
# traced as used, plus a self-contained server.js — no `public/` directory
# exists in this app today, so it's intentionally not copied here.
COPY --from=builder --chown=caskyui:nodejs /app/.next/standalone ./
COPY --from=builder --chown=caskyui:nodejs /app/.next/static ./.next/static

USER caskyui
EXPOSE 3000
CMD ["node", "server.js"]

LABEL org.opencontainers.image.source="https://github.com/casky-ai/casky-runner"
