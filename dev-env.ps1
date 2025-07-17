# AT Protocol Development Environment Management Script
param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "restart", "logs", "test", "status", "clean")]
    [string]$Action = "start",
    
    [Parameter(Position=1)]
    [string]$Service = "",
    
    [switch]$Build,
    [switch]$Follow
)

$ComposeFile = "docker-compose.dev.yml"

function Show-Usage {
    Write-Host "AT Protocol Development Environment Manager" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\dev-env.ps1 [action] [options]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Cyan
    Write-Host "  start     - Start the development environment (default)"
    Write-Host "  stop      - Stop all services"
    Write-Host "  restart   - Restart all services"
    Write-Host "  logs      - Show logs for all services"
    Write-Host "  test      - Run tests with test databases"
    Write-Host "  status    - Show status of all services"
    Write-Host "  clean     - Remove all containers and volumes"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Build    - Force rebuild of containers"
    Write-Host "  -Follow   - Follow logs in real-time"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\dev-env.ps1 start -Build"
    Write-Host "  .\dev-env.ps1 logs -Follow"
    Write-Host "  .\dev-env.ps1 test"
}

function Start-Environment {
    Write-Host "Starting AT Protocol Development Environment..." -ForegroundColor Green
    
    $buildFlag = if ($Build) { "--build" } else { "" }
    
    if ($buildFlag) {
        Write-Host "Building containers..." -ForegroundColor Yellow
        docker-compose -f $ComposeFile up -d $buildFlag
    } else {
        docker-compose -f $ComposeFile up -d
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Environment started successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Services available at:" -ForegroundColor Cyan
        Write-Host "  PDS:           http://localhost:2583"
        Write-Host "  Bsky AppView:  http://localhost:2584"
        Write-Host "  Ozone:         http://localhost:2585"
        Write-Host "  PLC Directory: http://localhost:2586"
        Write-Host "  PostgreSQL:    localhost:5432 (dev) / localhost:5433 (test)"
        Write-Host "  Redis:         localhost:6379 (dev) / localhost:6380 (test)"
    }
}

function Stop-Environment {
    Write-Host "Stopping AT Protocol Development Environment..." -ForegroundColor Yellow
    docker-compose -f $ComposeFile down
}

function Restart-Environment {
    Write-Host "Restarting AT Protocol Development Environment..." -ForegroundColor Yellow
    Stop-Environment
    Start-Sleep -Seconds 2
    Start-Environment
}

function Show-Logs {
    if ($Follow) {
        docker-compose -f $ComposeFile logs -f
    } else {
        docker-compose -f $ComposeFile logs --tail=50
    }
}

function Run-Tests {
    Write-Host "Running AT Protocol tests..." -ForegroundColor Green
    
    # Start test databases
    Write-Host "Starting test databases..." -ForegroundColor Yellow
    docker-compose -f $ComposeFile up -d postgres-test redis-test
    
    # Wait for databases to be ready
    Write-Host "Waiting for test databases to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    
    # Run tests
    Write-Host "Running tests..." -ForegroundColor Green
    docker-compose -f $ComposeFile exec atproto-dev pnpm test
    
    Write-Host "Tests completed!" -ForegroundColor Green
}

function Show-Status {
    Write-Host "AT Protocol Development Environment Status:" -ForegroundColor Green
    docker-compose -f $ComposeFile ps
}

function Clean-Environment {
    Write-Host "Cleaning AT Protocol Development Environment..." -ForegroundColor Red
    Write-Host "This will remove all containers and volumes. Are you sure? (y/N)" -ForegroundColor Yellow
    $confirmation = Read-Host
    
    if ($confirmation -eq 'y' -or $confirmation -eq 'Y') {
        docker-compose -f $ComposeFile down -v --remove-orphans
        docker system prune -f
        Write-Host "Environment cleaned!" -ForegroundColor Green
    } else {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
    }
}

# Main execution
switch ($Action.ToLower()) {
    "start" { Start-Environment }
    "stop" { Stop-Environment }
    "restart" { Restart-Environment }
    "logs" { Show-Logs }
    "test" { Run-Tests }
    "status" { Show-Status }
    "clean" { Clean-Environment }
    default { Show-Usage }
}
