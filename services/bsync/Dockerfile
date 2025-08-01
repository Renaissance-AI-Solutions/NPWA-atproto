FROM node:18-alpine as build

RUN corepack enable

WORKDIR /app

COPY ./package.json ./
RUN corepack prepare --activate

# Move files into the image and install
COPY ./*.* ./
# NOTE bsync's transitive dependencies go here: if that changes, this needs to be updated.
COPY ./tsconfig ./tsconfig
COPY ./packages/bsync ./packages/bsync
COPY ./packages/common ./packages/common
COPY ./packages/common-web ./packages/common-web
COPY ./packages/syntax ./packages/syntax
COPY ./services/bsync ./services/bsync


# install all deps
RUN pnpm install --frozen-lockfile > /dev/null
# build all packages with external node_modules
RUN pnpm build > /dev/null
# clean up
RUN rm -rf node_modules
# install only prod deps, hoisted to root node_modules dir
RUN pnpm install --prod --shamefully-hoist --frozen-lockfile --prefer-offline > /dev/null

WORKDIR services/bsync

# Uses assets from build stage to reduce build size
FROM node:18-alpine

RUN apk add --update dumb-init

# Avoid zombie processes, handle signal forwarding
ENTRYPOINT ["dumb-init", "--"]

WORKDIR /app/services/bsync
COPY --from=build /app /app

EXPOSE 3000
ENV BSYNC_PORT=3000
ENV NODE_ENV=production

# https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md#non-root-user
USER node
CMD ["node", "--enable-source-maps", "index.js"]

LABEL org.opencontainers.image.source=https://github.com/bluesky-social/atproto
LABEL org.opencontainers.image.description="Bsync"
LABEL org.opencontainers.image.licenses=MIT
