# Deployment Strategy

This document outlines the deployment strategy for hamrah-api.

## Environments

### Production (`hamrah-api`)
- **Trigger**: Push to `main` branch
- **Config**: `wrangler.toml`
- **Database**: `prod-hamrah-app-auth`
- **URL**: `https://api.hamrah.app`

### Preview (`hamrah-api-preview`)
- **Trigger**: Pull requests to `main` branch
- **Config**: `wrangler.preview.toml`  
- **Database**: `dev-hamrah-app-auth` (requires setup)
- **URL**: `https://hamrah-api-preview.{account}.workers.dev`

## Workflow Jobs

### 1. Test Job
- Runs on all events (push to main, pull requests)
- Performs: formatting check, linting (clippy), tests
- Must pass before any deployment

### 2. Deploy Preview Job
- Runs only on pull requests
- Depends on test job passing
- Deploys to preview environment for testing changes

### 3. Deploy Production Job  
- Runs only on push to main branch
- Depends on test job passing
- Deploys to production environment

## Setup Requirements

1. **Cloudflare Secrets** (in GitHub repository settings):
   - `CLOUDFLARE_API_TOKEN`
   - `CLOUDFLARE_ACCOUNT_ID`

2. **Preview Database Setup**:
   - Create a dev D1 database in Cloudflare dashboard
   - Update `database_id` in `wrangler.preview.toml`
   - Run database migrations on the dev database

## Benefits

- ✅ **No accidental production deploys**: PRs only deploy to preview
- ✅ **Isolated testing**: Each PR gets its own preview deployment  
- ✅ **Safe main branch**: Only tested, approved code reaches production
- ✅ **Easy rollbacks**: Production deployments are controlled and traceable