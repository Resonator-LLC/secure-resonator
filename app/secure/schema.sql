
create table if not exists orgs (
  id bigserial primary key,
  name text not null,
  created_at timestamptz not null default now()
);
create table if not exists users (
  id bigserial primary key,
  sub text unique not null,
  email text,
  name text,
  org_id bigint not null references orgs(id),
  created_at timestamptz not null default now()
);
create table if not exists agent_tokens (
  id bigserial primary key,
  org_id bigint not null references orgs(id),
  label text not null,
  token_hash text unique not null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create table if not exists hosts (
  id bigserial primary key,
  org_id bigint not null references orgs(id),
  name text not null,
  os text,
  source text not null default 'manual',
  last_report_at timestamptz,
  unique(org_id, name)
);
create table if not exists components (
  id bigserial primary key,
  host_id bigint not null references hosts(id) on delete cascade,
  ecosystem text not null,
  name text not null,
  version text not null,
  purl text,
  unique(host_id, ecosystem, name, version)
);
create table if not exists advisories (
  id text primary key,
  summary text,
  details text,
  severity text,
  aliases text[] default '{}',
  published timestamptz,
  modified timestamptz,
  raw jsonb,
  fetched_at timestamptz not null default now()
);
create table if not exists findings (
  id bigserial primary key,
  component_id bigint not null references components(id) on delete cascade,
  advisory_id text not null references advisories(id),
  fixed_version text,
  status text not null default 'open',
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  unique(component_id, advisory_id)
);
create table if not exists proposals (
  id bigserial primary key,
  org_id bigint not null references orgs(id),
  host_id bigint references hosts(id) on delete cascade,
  finding_id bigint references findings(id) on delete cascade,
  title text not null,
  rationale text,
  steps jsonb not null,
  status text not null default 'proposed',
  proposed_by text not null default 'rule-engine',
  decided_by bigint references users(id),
  decided_at timestamptz,
  result jsonb,
  created_at timestamptz not null default now(),
  unique(finding_id)
);
create table if not exists events (
  id bigserial primary key,
  org_id bigint references orgs(id),
  kind text not null,
  message text not null,
  ref jsonb,
  created_at timestamptz not null default now()
);
create table if not exists scan_state (
  component_id bigint primary key references components(id) on delete cascade,
  scanned_at timestamptz not null default now()
);
create index if not exists findings_status_idx on findings(status);
create index if not exists events_org_idx on events(org_id, id desc);
