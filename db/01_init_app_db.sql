-- ==========================================
-- Application Tables
-- ==========================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- Connections Table
CREATE TABLE IF NOT EXISTS public.connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'oci')),
    credentials JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);


-- Scan Jobs Table
CREATE TABLE IF NOT EXISTS public.scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES public.connections(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);


-- Resources Table
CREATE TABLE IF NOT EXISTS public.resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES public.scan_jobs(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL,
    provider_resource_id TEXT NOT NULL,
    name TEXT NOT NULL,
    region TEXT,
    configuration JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);


-- Rules Table
CREATE TABLE IF NOT EXISTS public.rules (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'oci')),
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN ('CRITICAL', 'HIGH', 'WARNING', 'MEDIUM', 'INFO')
    ),
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL
);


-- Findings Table
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES public.scan_jobs(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES public.resources(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL REFERENCES public.rules(id) ON UPDATE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL')),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);


-- ==========================================
-- Indexes
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_connections_user
ON public.connections(user_id);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_connection
ON public.scan_jobs(connection_id);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user
ON public.scan_jobs(user_id);

CREATE INDEX IF NOT EXISTS idx_resources_scan
ON public.resources(scan_job_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan
ON public.findings(scan_job_id);

CREATE INDEX IF NOT EXISTS idx_findings_resource
ON public.findings(resource_id);