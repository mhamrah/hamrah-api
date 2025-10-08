# Deployment Guide

## Cloud Run Service

The application is deployed to Google Cloud Run:

- **Project**: hamrah-ai
- **Region**: us-central1
- **Service**: hamrah-api
- **URL**: https://hamrah-api-a7tefmgk7q-uc.a.run.app

## Configuration

### Required Secrets

Create the following secrets in Google Cloud Secret Manager:

```bash
# Database connection string
gcloud secrets create DATABASE_URL \
  --project=hamrah-ai \
  --replication-policy=automatic

# JWT secret for authentication
gcloud secrets create JWT_SECRET \
  --project=hamrah-ai \
  --replication-policy=automatic
```

Set secret values:

```bash
# Set DATABASE_URL
echo -n "postgresql://user:pass@host/db" | gcloud secrets versions add DATABASE_URL --data-file=-

# Set JWT_SECRET
echo -n "your-secure-random-string" | gcloud secrets versions add JWT_SECRET --data-file=-
```

Grant Cloud Run access to secrets:

```bash
gcloud secrets add-iam-policy-binding DATABASE_URL \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding JWT_SECRET \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Artifact Registry

Create Artifact Registry repository for container images:

```bash
gcloud artifacts repositories create hamrah \
  --repository-format=docker \
  --location=us-central1 \
  --project=hamrah-ai
```

## GitHub Actions Setup

### Required Secrets

Configure the following secrets in your GitHub repository settings:

1. **WIF_PROVIDER**: Workload Identity Federation provider
   ```
   projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID
   ```

2. **GCP_SA_EMAIL**: Service account email
   ```
   github-actions@hamrah-ai.iam.gserviceaccount.com
   ```

### Workload Identity Federation Setup

```bash
# Create workload identity pool
gcloud iam workload-identity-pools create github-pool \
  --project=hamrah-ai \
  --location=global \
  --display-name="GitHub Actions Pool"

# Create provider
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --project=hamrah-ai \
  --location=global \
  --workload-identity-pool=github-pool \
  --display-name="GitHub Provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# Create service account
gcloud iam service-accounts create github-actions \
  --project=hamrah-ai \
  --display-name="GitHub Actions"

# Grant permissions
gcloud projects add-iam-policy-binding hamrah-ai \
  --member="serviceAccount:github-actions@hamrah-ai.iam.gserviceaccount.com" \
  --role="roles/run.admin"

gcloud projects add-iam-policy-binding hamrah-ai \
  --member="serviceAccount:github-actions@hamrah-ai.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser"

gcloud artifacts repositories add-iam-policy-binding hamrah \
  --location=us-central1 \
  --member="serviceAccount:github-actions@hamrah-ai.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

# Allow GitHub to impersonate service account
gcloud iam service-accounts add-iam-policy-binding github-actions@hamrah-ai.iam.gserviceaccount.com \
  --project=hamrah-ai \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_GITHUB_USERNAME/hamrah-api"
```

## Manual Deployment

To deploy manually:

```bash
# Build and push image
IMAGE="us-central1-docker.pkg.dev/hamrah-ai/hamrah/hamrah-api:$(git rev-parse --short HEAD)"
docker build -t "$IMAGE" .
docker push "$IMAGE"

# Deploy to Cloud Run
gcloud run deploy hamrah-api \
  --project hamrah-ai \
  --region us-central1 \
  --image "$IMAGE" \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances 10 \
  --memory 512Mi \
  --cpu 1 \
  --port 8080 \
  --no-cpu-throttling \
  --startup-probe httpGet.path=/healthz,httpGet.port=8080,initialDelaySeconds=10,periodSeconds=10,timeoutSeconds=3,failureThreshold=3 \
  --liveness-probe httpGet.path=/healthz,httpGet.port=8080,initialDelaySeconds=30,periodSeconds=30,timeoutSeconds=3,failureThreshold=3 \
  --set-env-vars "RUST_LOG=info" \
  --set-secrets "DATABASE_URL=DATABASE_URL:latest,JWT_SECRET=JWT_SECRET:latest"
```

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/cloud-run.yml`) automatically:

1. Authenticates to Google Cloud using Workload Identity Federation
2. Builds the Docker image
3. Pushes to Artifact Registry
4. Deploys to Cloud Run

Deployments trigger on:
- Push to `main` branch
- Manual workflow dispatch

## Database Migrations

Migrations run automatically on application startup. The service will:
1. Connect to the database
2. Run pending migrations from `./migrations`
3. Start accepting requests

## Health Checks

- **Health endpoint**: `GET /healthz`
- **Ready endpoint**: `GET /readyz`

## Monitoring

View logs and metrics:

```bash
# View logs
gcloud run services logs tail hamrah-api --region=us-central1

# View service details
gcloud run services describe hamrah-api --region=us-central1
```
