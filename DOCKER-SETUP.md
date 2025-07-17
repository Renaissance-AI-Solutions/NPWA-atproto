# Complete Development Environment Setup Guide

This guide provides comprehensive instructions for setting up and running the full application stack, including both backend services and frontend, with easy switching between different development environments.

> **🚀 Quick Start**: Use the automated environment switcher script `.\switch-environment.ps1 [tisocial|atproto]` to quickly switch between environments with a single command!

## Overview

The development setup supports two main environments:

1. **TISocial Environment**: Original Docker-based setup with custom PDS and AppView services
2. **AT Protocol Development Environment**: Official AT Protocol development environment with full Bluesky compatibility

## Prerequisites

### Required Software
- **Node.js 18+** (managed via nvm)
- **pnpm** (package manager)
- **Docker Desktop** (for databases and services)
- **jq** (JSON processor)
- **Git**

### Installation Commands
```powershell
# Install Node.js via nvm (if not already installed)
nvm install 18
nvm use 18

# Install pnpm globally
npm install -g pnpm

# Install jq via winget
winget install jqlang.jq

# Verify Docker is running
docker --version
```

## Directory Structure
```
C:\Dev\TISocial\
├── NPWA-atproto\          # AT Protocol backend services
├── NPWA-social-app\       # Frontend social application
├── docker-compose.yml     # TISocial environment configuration
└── start-atproto-dev.bat  # Quick start script for AT Protocol
```

## Environment 1: TISocial Development Environment

### Starting TISocial Environment
```powershell
cd C:\Dev\TISocial
docker-compose up -d --build
```

### Services & Ports (TISocial)
- 🌐 **Frontend (Web)**: http://localhost:19006
- 🌐 **Frontend (bskyweb)**: http://localhost:8100
- 🌞 **PDS (Personal Data Server)**: http://localhost:3000
- 🌅 **AppView (Bsky)**: http://localhost:3001
- 🐘 **PostgreSQL**: localhost:5432
- 🔴 **Redis**: localhost:6379

### Frontend Configuration (TISocial)
The frontend automatically uses TISocial services when no `.env.local` file is present, or when `.env.local` contains:

```env
# TISocial Environment Configuration
EXPO_PUBLIC_API_URL=http://localhost:3000
EXPO_PUBLIC_APP_VIEW_URL=http://localhost:3001
EXPO_PUBLIC_USE_LOCAL_SERVICES=true
NODE_ENV=development
```

## Environment 2: AT Protocol Development Environment

### Starting AT Protocol Environment

#### Option A: Quick Start Script (Recommended)
```powershell
# Run the automated startup script
C:\Dev\TISocial\start-atproto-dev.bat
```

This script will:
1. Start Docker services (PostgreSQL and Redis)
2. Start AT Protocol backend services
3. Start the frontend social app
4. Open separate terminal windows for each service

#### Option B: Manual Step-by-Step

**Step 1: Start Docker Services**
```powershell
cd C:\Dev\TISocial\NPWA-atproto
docker compose --file packages/dev-infra/docker-compose.yaml up --wait --force-recreate db_test redis_test
```

**Step 2: Start AT Protocol Backend Services**
```powershell
C:\Dev\TISocial\NPWA-atproto\start-dev-env.bat
```

**Step 3: Configure Frontend for AT Protocol**
Create or update `C:\Dev\TISocial\NPWA-social-app\.env.local`:

```env
# AT Protocol Development Environment Configuration
EXPO_PUBLIC_API_URL=http://localhost:2583
EXPO_PUBLIC_APP_VIEW_URL=http://localhost:2584
EXPO_PUBLIC_USE_LOCAL_SERVICES=true
NODE_ENV=development
```

**Step 4: Start Frontend**
```powershell
cd C:\Dev\TISocial\NPWA-social-app
yarn web
```

### Services & Ports (AT Protocol)
- 🔍 **Dev-env introspection server**: http://localhost:2581
- 👤 **DID Placeholder server**: http://localhost:2582
- 🌞 **Personal Data server (PDS)**: http://localhost:2583
- 🌅 **Bsky Appview**: http://localhost:2584
- 🗼 **Ozone server**: http://localhost:2587
- 🤖 **Feed Generators**: http://localhost:51425 and http://localhost:51428
- 🌐 **Frontend (Web)**: http://localhost:19006
- 🐘 **PostgreSQL**: localhost:5433
- 🔴 **Redis**: localhost:6380

## Frontend Environment Switching

The frontend automatically detects which backend environment to use based on the `.env.local` file in the `NPWA-social-app` directory.

### Quick Environment Switching (Recommended)

Use the automated environment switcher script:

```powershell
# Switch to TISocial environment
.\switch-environment.ps1 tisocial

# Switch to AT Protocol environment
.\switch-environment.ps1 atproto

# Switch without starting frontend
.\switch-environment.ps1 atproto -SkipFrontend
```

This script will:
1. Stop all running services from both environments
2. Update the frontend configuration (`.env.local`)
3. Start the requested backend environment
4. Start the frontend in a new terminal window

### Manual Environment Switching

### Switching to TISocial Environment

1. **Stop AT Protocol services** (if running):
   ```powershell
   # Stop AT Protocol backend (Ctrl+C in terminal)
   # Stop Docker services
   cd C:\Dev\TISocial\NPWA-atproto
   docker compose --file packages/dev-infra/docker-compose.yaml down
   ```

2. **Update frontend configuration**:
   Edit or create `C:\Dev\TISocial\NPWA-social-app\.env.local`:
   ```env
   # TISocial Environment Configuration
   EXPO_PUBLIC_API_URL=http://localhost:3000
   EXPO_PUBLIC_APP_VIEW_URL=http://localhost:3001
   EXPO_PUBLIC_USE_LOCAL_SERVICES=true
   NODE_ENV=development
   ```

3. **Start TISocial environment**:
   ```powershell
   cd C:\Dev\TISocial
   docker-compose up -d --build
   ```

4. **Start frontend** (if not already running):
   ```powershell
   cd C:\Dev\TISocial\NPWA-social-app
   yarn web
   ```

### Switching to AT Protocol Environment

1. **Stop TISocial services** (if running):
   ```powershell
   cd C:\Dev\TISocial
   docker-compose down
   ```

2. **Update frontend configuration**:
   Edit or create `C:\Dev\TISocial\NPWA-social-app\.env.local`:
   ```env
   # AT Protocol Development Environment Configuration
   EXPO_PUBLIC_API_URL=http://localhost:2583
   EXPO_PUBLIC_APP_VIEW_URL=http://localhost:2584
   EXPO_PUBLIC_USE_LOCAL_SERVICES=true
   NODE_ENV=development
   ```

3. **Start AT Protocol environment**:
   ```powershell
   # Quick start (recommended)
   C:\Dev\TISocial\start-atproto-dev.bat

   # OR manual start
   cd C:\Dev\TISocial\NPWA-atproto
   docker compose --file packages/dev-infra/docker-compose.yaml up --wait --force-recreate db_test redis_test
   C:\Dev\TISocial\NPWA-atproto\start-dev-env.bat
   ```

4. **Start frontend** (if not already running):
   ```powershell
   cd C:\Dev\TISocial\NPWA-social-app
   yarn web
   ```

### Environment Configuration Details

The frontend uses these environment variables to determine backend connections:

| Variable | TISocial | AT Protocol |
|----------|----------|-------------|
| `EXPO_PUBLIC_API_URL` | `http://localhost:3000` | `http://localhost:2583` |
| `EXPO_PUBLIC_APP_VIEW_URL` | `http://localhost:3001` | `http://localhost:2584` |
| `EXPO_PUBLIC_USE_LOCAL_SERVICES` | `true` | `true` |

### Service Mapping

**TISocial Environment:**
```
Frontend Service          →  TISocial Service
LOCAL_DEV_SERVICE         →  http://localhost:3000 (PDS)
PUBLIC_BSKY_SERVICE       →  http://localhost:3001 (AppView)
EMBED_SERVICE             →  http://localhost:3001 (AppView)
GIF_SERVICE               →  http://localhost:3001 (AppView)
```

**AT Protocol Environment:**
```
Frontend Service          →  AT Protocol Service
LOCAL_DEV_SERVICE         →  http://localhost:2583 (PDS)
PUBLIC_BSKY_SERVICE       →  http://localhost:2584 (AppView)
EMBED_SERVICE             →  http://localhost:2584 (AppView)
GIF_SERVICE               →  http://localhost:2584 (AppView)
```

## Development Features

### TISocial Environment Features
- Custom PDS and AppView implementations
- Integrated with TISocial-specific features
- Docker-based for easy deployment
- Persistent data storage

### AT Protocol Environment Features
- **Official AT Protocol implementation** with full Bluesky compatibility
- **Mock Data & Test Accounts**: Automatically creates realistic test accounts
- **Complete Social Features**: Posts, follows, likes, reposts, replies
- **Content Moderation**: Labeler services and moderation tools
- **Feed Algorithms**: Custom feed generators for testing
- **Media Support**: Image and video upload/processing
- **Real-time Updates**: Live feed updates and notifications

### Test Data (AT Protocol Environment)
The AT Protocol environment automatically generates:
- Multiple test user accounts with unique DIDs
- User profiles with display names, avatars, and bios
- Sample posts with various content types
- Social interactions (follows, likes, reposts)
- Content labels and moderation actions
- Custom feed algorithms

## Testing

### Backend Tests
```powershell
# TISocial environment
cd C:\Dev\TISocial
docker-compose exec pds npm test

# AT Protocol environment
cd C:\Dev\TISocial\NPWA-atproto
pnpm test
```

### Frontend Tests
```powershell
cd C:\Dev\TISocial\NPWA-social-app
yarn test
```

### End-to-End Tests
```powershell
cd C:\Dev\TISocial\NPWA-social-app
yarn e2e:mock-server  # Start mock server
yarn e2e:run          # Run E2E tests
```

## Troubleshooting

### Port Conflicts
If you get port conflicts between environments:

```powershell
# Check which ports are in use
netstat -ano | findstr ":3000\|:3001\|:2583\|:2584"

# Stop TISocial environment
cd C:\Dev\TISocial
docker-compose down

# Stop AT Protocol environment
cd C:\Dev\TISocial\NPWA-atproto
docker compose --file packages/dev-infra/docker-compose.yaml down
# Also stop the Node.js process (Ctrl+C in terminal)
```

### Frontend Not Connecting to Backend
1. **Check `.env.local` configuration** in `NPWA-social-app` directory
2. **Verify backend services are running** on expected ports
3. **Clear browser cache** and restart frontend
4. **Check browser developer tools** for connection errors

### Database Connection Issues
```powershell
# TISocial environment
cd C:\Dev\TISocial
docker-compose restart postgres redis

# AT Protocol environment
cd C:\Dev\TISocial\NPWA-atproto
docker compose --file packages/dev-infra/docker-compose.yaml restart db_test redis_test
```

### Windows File Path Issues (AT Protocol)
The AT Protocol environment handles Windows-specific path encoding automatically:
- DIDs with colons are URL-encoded in file paths (`:` becomes `%3A`)
- Temporary files are created in Windows-compatible locations

### Build Issues
```powershell
# TISocial environment
cd C:\Dev\TISocial
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# AT Protocol environment
cd C:\Dev\TISocial\NPWA-atproto
pnpm clean
pnpm install
pnpm build
```

### Frontend Build Issues
```powershell
cd C:\Dev\TISocial\NPWA-social-app
rm -rf node_modules
yarn install
yarn web
```

## Development Workflow

### Daily Development Process
1. **Choose your environment** (TISocial or AT Protocol)
2. **Update `.env.local`** to match your chosen environment
3. **Start backend services** for your chosen environment
4. **Start frontend** with `yarn web`
5. **Make changes** to code
6. **Test changes** (both environments support hot reloading)
7. **Run tests** before committing
8. **Stop services** when done

### Making Backend Changes
- **TISocial**: Edit files in Docker containers or rebuild images
- **AT Protocol**: Edit files in `NPWA-atproto/packages/` (supports hot reloading)

### Making Frontend Changes
1. Edit files in `NPWA-social-app/src/`
2. Changes automatically refresh in browser
3. Check browser developer tools for errors
4. Test with both backend environments if needed

### Switching Between Environments
You can switch environments without losing work:
1. Stop current backend services
2. Update `.env.local` configuration
3. Start new backend services
4. Frontend will automatically connect to new backend

## API Testing Examples

### Testing TISocial APIs
```bash
# Test PDS
curl http://localhost:3000/health

# Test AppView
curl http://localhost:3001/health
```

### Testing AT Protocol APIs
```bash
# Test PDS (Personal Data Server)
curl http://localhost:2583/xrpc/com.atproto.server.describeServer

# Test AppView
curl http://localhost:2584/xrpc/app.bsky.actor.getProfiles

# Test DID resolution
curl http://localhost:2582/did:plc:example
```

## Database Access

### TISocial Environment
```powershell
# Connect to PostgreSQL
docker exec -it tisocial-postgres-1 psql -U postgres -d tisocial

# Connect to Redis
docker exec -it tisocial-redis-1 redis-cli
```

### AT Protocol Environment
```powershell
# Connect to PostgreSQL
docker exec -it dev-infra-db_test-1 psql -U pg -d postgres

# Connect to Redis
docker exec -it dev-infra-redis_test-1 redis-cli
```

## Production Deployment

### Building for Production
```powershell
# Build AT Protocol services
cd C:\Dev\TISocial\NPWA-atproto
pnpm build

# Build frontend
cd C:\Dev\TISocial\NPWA-social-app
yarn build-web
```

### Environment Variables for Production
Create production `.env` files with appropriate URLs:
```env
# Production configuration example
EXPO_PUBLIC_API_URL=https://your-pds-domain.com
EXPO_PUBLIC_APP_VIEW_URL=https://your-appview-domain.com
EXPO_PUBLIC_USE_LOCAL_SERVICES=false
NODE_ENV=production
```

## Additional Resources
- **AT Protocol Documentation**: https://atproto.com/
- **Bluesky Social App**: https://github.com/bluesky-social/social-app
- **AT Protocol Specification**: https://atproto.com/specs/atp
- **Docker Documentation**: https://docs.docker.com/
- **Node.js Documentation**: https://nodejs.org/docs/
