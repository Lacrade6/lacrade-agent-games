# SPDX-License-Identifier: MIT
FROM node:24-bookworm-slim

WORKDIR /app

# Install dependencies first (cached layer).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy the agent code (circuits are NOT in the image context — see .dockerignore).
COPY src ./src
COPY scripts ./scripts

# Download circuit artifacts from the official zkVerify URLs at build time
# and verify their SHA-256 against the pinned values in src/circuits.mjs.
RUN node scripts/download-circuits.mjs ./circuits

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "src/server.mjs"]
