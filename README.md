# GCP SQL Scaling Scheduler

A lightweight HTTP service written in Go for scaling Google Cloud SQL instances on demand — change tier (CPU/RAM) and database flags via simple REST API calls. Designed to be triggered by **Cloud Scheduler**, **Cloud Run**, or any HTTP client.

---

## How It Works

The service exposes two endpoints:

- `GET /check` — list all Cloud SQL instances in the project with their current state and tier
- `POST /action?do=update` — update a Cloud SQL instance's tier and/or database flags

Cloud Scheduler can hit these endpoints on a cron schedule to scale up before peak hours and scale down after, saving costs without manual intervention.

```
Cloud Scheduler ──► Cloud Run / Cloud Functions ──► Cloud SQL Admin API
     (cron)               (this service)               (patch instance)
```

---

## Prerequisites

- Go 1.24+
- A GCP project with Cloud SQL instances
- A **Service Account** with the `Cloud SQL Admin` role
- Service account key file (`service_account.json`) placed in the project root

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/dimaspratama04/gcp-sql-scaling-scheduler.git
cd gcp-sql-scaling-scheduler
```

**2. Create a Service Account and download the key**
```bash
# Create service account
gcloud iam service-accounts create sql-scaling-sa \
  --display-name="SQL Scaling Scheduler"

# Grant Cloud SQL Admin role
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:sql-scaling-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudsql.admin"

# Download key
gcloud iam service-accounts keys create service_account.json \
  --iam-account=sql-scaling-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

**3. Configure environment variables**

Create a `.env` file:
```env
PROJECT_ID=your-gcp-project-id
PORT=8080
ENV=local   # omit or set to "production" on deployed environments
```

**4. Run locally**
```bash
go mod download
go run main.go
```

---

## Docker

Build and run using the provided Dockerfile:

```bash
# Build
docker build -f Dockerfile.scaling -t sql-scaling-scheduler .

# Run
docker run -p 8080:8080 \
  -e PROJECT_ID=your-gcp-project-id \
  -e PORT=8080 \
  sql-scaling-scheduler
```

> **Note:** Make sure `service_account.json` is present in the project directory before building, as it gets copied into the image.

---

## API Reference

### `GET /check`

Returns a list of all Cloud SQL instances in the project.

**Response:**
```json
{
  "status_code": 200,
  "status_text": "OK",
  "message": "Successfully fetched all instances.",
  "timestamp": "2025-01-01T08:00:00Z",
  "data": [
    {
      "name": "my-sql-instance",
      "database_version": "MYSQL_8_0",
      "region": "asia-southeast2",
      "state": "RUNNABLE",
      "tier": "db-custom-2-7680"
    }
  ]
}
```

---

### `POST /action?do=update`

Updates the tier and/or database flags of a Cloud SQL instance.

**Request Body:**
```json
{
  "instance_name": "my-sql-instance",
  "tier": "db-custom-4-15360",
  "flags": {
    "max_connections": "500",
    "slow_query_log": "on"
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `instance_name` | string | ✅ | Cloud SQL instance name |
| `tier` | string | ✅ | Target machine type. Format: `db-custom-<cpus>-<memory_mb>` |
| `flags` | object | ❌ | Key-value map of database flags to apply |

**Tier Format:** `db-custom-{vCPUs}-{MemoryMB}`

Examples:
- `db-custom-2-7680` → 2 vCPU, 7.5 GB RAM
- `db-custom-4-15360` → 4 vCPU, 15 GB RAM
- `db-custom-8-30720` → 8 vCPU, 30 GB RAM

**Success Response:**
```json
{
  "status_code": 200,
  "status_text": "OK",
  "message": "Instances succesfully updated, for detail check your console.",
  "timestamp": "2025-01-01T08:00:00Z",
  "data": ""
}
```

**Error Response:**
```json
{
  "status_code": 400,
  "status_text": "Bad Request",
  "message": "Invalid tier format. Only db-custom-<cpus>-<memory> allowed",
  "timestamp": "2025-01-01T08:00:00Z",
  "error_type": "client_error",
  "error_description": ""
}
```

---

## Deploy to Cloud Run

```bash
# Build and push image to Artifact Registry
docker build -f Dockerfile.scaling -t asia-southeast1-docker.pkg.dev/YOUR_PROJECT/YOUR_REPO/sql-scaling-scheduler:latest .
docker push asia-southeast1-docker.pkg.dev/YOUR_PROJECT/YOUR_REPO/sql-scaling-scheduler:latest

# Deploy to Cloud Run
gcloud run deploy sql-scaling-scheduler \
  --image asia-southeast1-docker.pkg.dev/YOUR_PROJECT/YOUR_REPO/sql-scaling-scheduler:latest \
  --region asia-southeast1 \
  --set-env-vars PROJECT_ID=YOUR_PROJECT_ID \
  --no-allow-unauthenticated
```

---

## Cloud Scheduler Integration

Create scheduled jobs to scale up in the morning and down at night:

```bash
# Scale UP at 08:00 WIB (01:00 UTC) on weekdays
gcloud scheduler jobs create http scale-up-job \
  --schedule="0 1 * * 1-5" \
  --uri="https://YOUR_CLOUD_RUN_URL/action?do=update" \
  --message-body='{"instance_name":"my-sql-instance","tier":"db-custom-4-15360"}' \
  --headers="Content-Type=application/json" \
  --time-zone="UTC" \
  --location=asia-southeast1

# Scale DOWN at 20:00 WIB (13:00 UTC) on weekdays
gcloud scheduler jobs create http scale-down-job \
  --schedule="0 13 * * 1-5" \
  --uri="https://YOUR_CLOUD_RUN_URL/action?do=update" \
  --message-body='{"instance_name":"my-sql-instance","tier":"db-custom-2-7680"}' \
  --headers="Content-Type=application/json" \
  --time-zone="UTC" \
  --location=asia-southeast1
```

---

## Project Structure

```
gcp-sql-scaling-scheduler/
├── main.go              # HTTP server, handlers, Cloud SQL API calls
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
├── Dockerfile.scaling   # Multi-stage Docker build
├── service_account.json # GCP service account key (DO NOT commit)
└── .env                 # Environment variables (DO NOT commit)
```

---

## Security Notes

- **Never commit** `service_account.json` or `.env` to version control. Add them to `.gitignore`.
- On Cloud Run, prefer using **Workload Identity** instead of a key file for production environments.
- Restrict the Cloud Run service with `--no-allow-unauthenticated` and use Cloud Scheduler's OIDC token for authentication.

---

## License

MIT
