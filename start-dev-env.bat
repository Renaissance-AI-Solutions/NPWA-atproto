@echo off
cd /d "C:\Dev\TISocial\NPWA-atproto"
set DB_POSTGRES_URL=postgresql://pg:password@127.0.0.1:5433/postgres
set REDIS_HOST=127.0.0.1:6380
set NODE_ENV=development
set LOG_ENABLED=true
echo Starting AT Protocol Development Environment with detailed logging...
echo Database: %DB_POSTGRES_URL%
echo Redis: %REDIS_HOST%
echo.
cd packages\dev-env
node --enable-source-maps dist/bin.js | pnpm exec pino-pretty
