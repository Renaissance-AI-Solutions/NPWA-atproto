@echo off
cd /d "C:\Dev\TISocial\NPWA-atproto"
set DB_POSTGRES_URL=postgresql://pg:password@127.0.0.1:5433/postgres
set REDIS_HOST=127.0.0.1:6380
set NODE_ENV=development
set LOG_ENABLED=true
set PGPORT=5433
set PGHOST=localhost
set PGUSER=pg
set PGPASSWORD=password
set PGDATABASE=postgres
set DB_TEST_POSTGRES_URL=postgresql://pg:password@127.0.0.1:5433/postgres
set REDIS_TEST_HOST=127.0.0.1:6380
echo Starting AT Protocol Development Environment with detailed logging...
echo Database: %DB_POSTGRES_URL%
echo Redis: %REDIS_HOST%
echo.
cd packages\dev-env
node --enable-source-maps dist/bin.js | pnpm exec pino-pretty
