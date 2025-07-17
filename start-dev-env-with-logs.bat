@echo off
cd /d "C:\Dev\TISocial\NPWA-atproto"

rem Create logs directory if it doesn't exist
if not exist "C:\Dev\TISocial\logs" mkdir "C:\Dev\TISocial\logs"

set DB_POSTGRES_URL=postgresql://pg:password@127.0.0.1:5433/postgres
set REDIS_HOST=127.0.0.1:6380
set NODE_ENV=development
set LOG_ENABLED=true
set LOG_LEVEL=debug

echo [%date% %time%] Starting AT Protocol Development Environment with detailed logging... >> "C:\Dev\TISocial\logs\backend-services.log"
echo [%date% %time%] Database: %DB_POSTGRES_URL% >> "C:\Dev\TISocial\logs\backend-services.log"
echo [%date% %time%] Redis: %REDIS_HOST% >> "C:\Dev\TISocial\logs\backend-services.log"
echo. >> "C:\Dev\TISocial\logs\backend-services.log"

echo Starting AT Protocol Development Environment with detailed logging...
echo Database: %DB_POSTGRES_URL%
echo Redis: %REDIS_HOST%
echo Logging to: C:\Dev\TISocial\logs\backend-services.log
echo.

cd packages\dev-env

rem Run with comprehensive logging
echo [%date% %time%] Starting dev-env... >> "C:\Dev\TISocial\logs\backend-services.log"
node --enable-source-maps dist/bin.js 2>&1 | pnpm exec pino-pretty 2>&1 | powershell -Command "$input | ForEach-Object { $_ | Out-File -FilePath 'C:\Dev\TISocial\logs\backend-services.log' -Append -Encoding UTF8; Write-Host $_ }"

rem If the above command fails, run without pino-pretty
if errorlevel 1 (
    echo [%date% %time%] Pino-pretty failed, running without it... >> "C:\Dev\TISocial\logs\backend-services.log"
    node --enable-source-maps dist/bin.js 2>&1 | powershell -Command "$input | ForEach-Object { $_ | Out-File -FilePath 'C:\Dev\TISocial\logs\backend-services.log' -Append -Encoding UTF8; Write-Host $_ }"
)

echo [%date% %time%] Dev-env process ended with exit code: %errorlevel% >> "C:\Dev\TISocial\logs\backend-services.log"