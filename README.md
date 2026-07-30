# Cloud Security Analyzer

A modular cloud security analyzer that discovers cloud resources, collects their configurations, evaluates security rules, and generates security findings. The architecture is provider-agnostic, making it easy to support multiple cloud platforms.

## Supported Providers

* AWS
* GCP
* OCI (Oracle Cloud Infrastructure)

---

## Getting Started

### 1. Setup Virtual Environment
Create a virtual environment and install the required dependencies:
```powershell
# Create venv
python -m venv .venv

# Install requirements - Windows PowerShell
.\.venv\Scripts\pip.exe install -r scanner/requirements.txt
```
```powershell
# Install requirements - Linux / macOS
source .venv/bin/activate
pip install -r scanner/requirements.txt
```

### 2. Run the Scanner
Execute the scanner CLI:
```powershell
python scanner/main.py
# If you get an error on command above, Then try:
.\.venv\Scripts\python.exe scanner/main.py
```

---

## Scanning Flow

```text
Select Provider
      │
      ▼
Request Credentials
      │
      ▼
Connect & Validate
      │
      ▼
Discover Resources
      │
      ▼
Collect Configurations
      │
      ▼
Execute Security Rules
      │
      ▼
Generate Findings
```

---

## Project Structure

```text
scanner/
│
├── main.py
├── providers/
│   ├── aws.py
│   └── gcp.py
└── rules/
    ├── common.py
    ├── executor.py
    └── aws/
        ├── ec2.py
        ├── iam.py
        └── s3.py
```

### Folders

* **main.py** – Entry point that orchestrates the scanning workflow.
* **providers/** – Cloud provider implementations (authentication, resource discovery, configuration collection).
* **rules/** – Rule engine and provider-specific security checks.
* **rules/aws/** – Security rules for AWS services (EC2, IAM, S3).
* **common.py** – Shared rule utilities.
* **executor.py** – Executes security rules against collected configurations.

---

## Design

The scanner follows a modular architecture:

* **Providers** communicate with cloud APIs.
* **Rules** evaluate resource configurations.
* **Main** orchestrates the scanning pipeline.

This design simplifies adding new cloud providers, services, and security rules while keeping the codebase maintainable.

---

## Local Backend & Database Setup (Docker)

This project runs a localized backend stack orchestrating user authentication, database management, migrations, and a REST API via **Docker Compose**.

### 🗄️ Database Tables (PostgreSQL)
The database contains 5 core normalized tables under the `public` schema with **Row-Level Security (RLS)** active:
1. **`connections`**: Holds cloud access credentials per user.
2. **`scan_jobs`**: Serves as our task queue (tracks `PENDING`, `RUNNING`, `COMPLETED`, `FAILED` jobs).
3. **`resources`**: Inventory database holding raw configurations inside `JSONB` columns.
4. **`rules`**: Static check reference catalog (e.g., `SEC-001`, `IAM-001`).
5. **`findings`**: Contains security alerts linking resources to rule statuses (`PASS`/`FAIL`).

---

### 🚀 Running the Local Stack
The entire environment can be initialized and launched automatically. 

#### 1. Setup Environment Variables
First, copy the example environment configuration to `.env` and adjust the values as needed:

```bash
# Copy the example environment file
cp example.env .env
```
*(On Windows PowerShell: `Copy-Item example.env .env`)*

#### 2. Start the Container Stack
Build and launch the complete container architecture in the background:

```bash
docker compose up --build -d
```


### 🔧 Initialization Pipeline

When you boot the container orchestration stack, the environment sets itself up through the following phases:

1. **Init Docker Compose**
   * Configures shared networking (`db_network`) and maps dependencies so that services start in their correct dependency order.
2. **Init Postgres (`db` service)**
   * Starts a `postgres:16.4-alpine` container.
   * Loads [00_init_auth.sql](file:///c:/Users/403/Documents/CloudRiskAnalyzer/db/00_init_auth.sql) in `/docker-entrypoint-initdb.d/` to create the `auth` schema, register default security roles (`authenticated`, `anon`), and set up the `auth.uid()` helper function.
3. **Init Auth (`auth` service)**
   * Launches `supabase/gotrue:v2.146.0` (Supabase's standalone auth engine) on port `9999`.
4. **Migrate Supabase**
   * During boot, the GoTrue auth service automatically connects to the Postgres database using `search_path=auth` and performs migration schemas to seed its internal user and session tables.
5. **Migrate Database**
   * Before booting the Express.js application, the `api` container runs `psql` to execute the database migrations.
   * It executes the migration script [01_init_db.sql](file:///c:/Users/403/Documents/CloudRiskAnalyzer/db/01_init_db.sql) against the database to construct the core application tables, performance indices, and enforce Row-Level Security policies.
6. **Init ExpressJS Backend (`api` service)**
   * Builds the backend microservice inside [api/](file:///c:/Users/403/Documents/CloudRiskAnalyzer/api) with `postgresql-client` installed.
   * Runs `npx prisma generate` to inspect both `public` and `auth` schemas to create database client models.
   * Boots the backend REST API on port `3000` once the migration step completes successfully.

