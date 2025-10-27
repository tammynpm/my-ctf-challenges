# ---- Base image ----
FROM node:20-alpine AS base
WORKDIR /app

# ---- Dependencies for build (dev deps included) ----
FROM base AS deps
COPY app/package*.json ./
RUN npm ci

# ---- Build the TypeScript -> dist/ ----
FROM deps AS build
COPY app/tsconfig*.json app/nest-cli.json ./
COPY app/src ./src
COPY app/public ./public
COPY app/assets ./assets
RUN npm run build

# ---- Production deps only (smaller runtime) ----
FROM base AS proddeps
COPY app/package*.json ./
RUN npm ci --omit=dev

# ---- Runtime image ----
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# copy prod node_modules and built app
COPY --from=proddeps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/public ./public
COPY --from=build /app/assets ./assets

EXPOSE 8888
CMD ["node", "dist/main.js"]
