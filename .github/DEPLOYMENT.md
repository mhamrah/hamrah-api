# Deployment Setup

This document explains how to set up GitHub Actions for automated deployment to Cloudflare Workers using the versioning system.

## Required Secrets

Add the following secrets to your GitHub repository settings (`Settings > Secrets and variables > Actions`):

### Required Secrets

1. **`CLOUDFLARE_API_TOKEN`**
   - Go to [Cloudflare Dashboard > My Profile > API Tokens](https://dash.cloudflare.com/profile/api-tokens)
   - Create a new token with:
     - Permissions: `Cloudflare Workers:Edit`, `Account:Read`, `Zone:Read`
     - Account Resources: Include your account
     - Zone Resources: Include your domain zones

2. **`CLOUDFLARE_ACCOUNT_ID`**
   - Found in your Cloudflare Dashboard sidebar
   - Or run: `npx wrangler whoami` to see your account ID

## Deployment Strategy

The workflow uses Cloudflare Workers versioning for branch-based deployments:

| Event | Deployment Type | Worker URL | Description |
|-------|----------------|------------|-------------|
| Push to `main` | Production | `api.hamrah.app/*` | Auto-deployed to production with custom domain |
| Pull Request | Branch Preview | `hamrah-api-{branch-name}.hamrah.workers.dev` | Temporary preview deployment |
| Push to other branches | Branch Preview | `hamrah-api-{branch-name}.hamrah.workers.dev` | Branch-specific preview |

## How It Works

### Production Deployments (main branch)
1. Code is built and uploaded as a new version
2. Version is tagged as `production-{commit}`
3. Version is automatically deployed to 100% of production traffic
4. Available at custom domain: `api.hamrah.app`

### Branch Deployments (feature branches & PRs)
1. Code is built and uploaded as a versioned worker
2. Version is tagged as `pr-{number}-{commit}` or `branch-{name}-{commit}`
3. Deployed as separate worker: `hamrah-api-{branch-name}.hamrah.workers.dev`
4. Each branch gets its own unique Workers subdomain
5. PR comments automatically include the preview URL

## DNS Setup

Configure only the production DNS record in Cloudflare:

```bash
# Production only
api.hamrah.app CNAME hamrah-api.hamrah.workers.dev
```

Branch deployments automatically get unique `*.workers.dev` subdomains.

## Manual Commands

```bash
# Install dependencies
cargo install worker-build
npm install -g wrangler

# Authenticate with Cloudflare
npx wrangler auth

# Build the project
worker-build --release

# Upload a new version
npx wrangler versions upload --message "Manual upload" --tag "manual"

# Deploy to production
npx wrangler versions deploy --version-id [VERSION_ID] --percentage 100

# Deploy to branch-specific worker
npx wrangler deploy --name hamrah-api-my-feature-branch
```

## Workflow Features

- ✅ Rust compilation with WASM target
- ✅ Code quality checks (clippy, fmt, tests)
- ✅ Dependency caching for faster builds
- ✅ Cloudflare Workers versioning system
- ✅ Branch-specific worker deployments
- ✅ Automatic PR comments with unique URLs
- ✅ Production deployments only from main branch

## Branch Naming

Branch names are automatically sanitized for worker names:
- `feature/auth-system` → `hamrah-api-feature-auth-system.hamrah.workers.dev`
- `bugfix/login_issue` → `hamrah-api-bugfix-login-issue.hamrah.workers.dev`
- `PR-123` → `hamrah-api-pr-123.hamrah.workers.dev`

## Troubleshooting

### Build Failures
- Ensure `worker-build` can compile your Rust code locally
- Check that all dependencies are compatible with WASM target
- Verify `Cargo.toml` has `crate-type = ["cdylib"]`

### Deployment Failures
- Verify API token has correct permissions for Workers versioning
- Check account ID is correct
- Ensure worker names don't exceed Cloudflare's limits

### Version Management
- View all versions: `npx wrangler versions list`
- View deployment status: `npx wrangler versions view [VERSION_ID]`
- Roll back: Deploy previous version with `wrangler versions deploy`