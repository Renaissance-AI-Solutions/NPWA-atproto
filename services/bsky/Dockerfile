FROM node:20.11-alpine as build

RUN corepack enable

WORKDIR /app

COPY ./package.json .
RUN corepack prepare --activate

# Copy relevant files from the monorepo root
COPY ./*.* ./
COPY ./tsconfig ./tsconfig
COPY ./packages ./packages
COPY ./services ./services
COPY ./lexicons ./lexicons
COPY ./interop-test-files ./interop-test-files

# install all deps
RUN pnpm install --frozen-lockfile
# build all packages with external node_modules
RUN pnpm build
# clean up
RUN rm -rf node_modules
# install only prod deps, hoisted to root node_modules dir
RUN pnpm install --prod --shamefully-hoist --frozen-lockfile --prefer-offline

WORKDIR services/bsky

# Uses assets from build stage to reduce build size
FROM node:20.11-alpine

# dumb-init is used to handle signals properly.
# runit is installed so it can be (optionally) used for logging via svlogd.
RUN apk add --update dumb-init runit postgresql-client


# Avoid zombie processes, handle signal forwarding
ENTRYPOINT ["dumb-init", "--"]

WORKDIR /app
COPY --from=build /app /app

EXPOSE 3000
ENV PORT=3000
ENV NODE_ENV=production
ENV NODE_PATH=./node_modules:/app/node_modules

# https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md#non-root-user
USER node
CMD ["node", "--heapsnapshot-signal=SIGUSR2", "--enable-source-maps", "/app/services/bsky/api.js"]

LABEL org.opencontainers.image.source=https://github.com/bluesky-social/atproto
LABEL org.opencontainers.image.description="Bsky App View"
LABEL org.opencontainers.image.licenses=MIT
