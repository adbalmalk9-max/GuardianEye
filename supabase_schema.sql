-- GuardianEye 5.0 schema
-- Safe to run after the existing GuardianEye systems/events tables.

create extension if not exists pgcrypto;

alter table public.systems
    add column if not exists ingest_token_hash text,
    add column if not exists agent_enabled boolean not null default true,
    add column if not exists agent_last_seen timestamptz;

create table if not exists public.security_events (
    id uuid primary key,
    system_id uuid not null references public.systems(id) on delete cascade,
    event_time timestamptz not null default now(),
    event_type text not null,
    attack_type text,
    severity text not null default 'Medium',
    confidence double precision not null default 0.5,
    source_ip inet,
    source_port integer,
    dest_port integer,
    protocol text,
    evidence text,
    status text not null default 'Open',
    detected_by text,
    raw_data jsonb
);

create table if not exists public.incidents (
    id uuid primary key,
    system_id uuid not null references public.systems(id) on delete cascade,
    title text not null,
    attack_type text not null,
    severity text not null default 'Medium',
    source_ip inet,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    event_count integer not null default 1,
    status text not null default 'Open',
    evidence_summary text,
    resolved_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists public.agent_heartbeats (
    id uuid primary key,
    system_id uuid not null references public.systems(id) on delete cascade,
    seen_at timestamptz not null default now(),
    hostname text,
    os_name text,
    agent_version text,
    cpu_percent double precision,
    memory_percent double precision,
    open_connections integer,
    monitored_logs jsonb
);

create index if not exists idx_security_events_system_time
    on public.security_events(system_id, event_time desc);

create index if not exists idx_security_events_source_ip
    on public.security_events(source_ip);

create index if not exists idx_incidents_system_status
    on public.incidents(system_id, status, last_seen desc);

create index if not exists idx_agent_heartbeats_system_time
    on public.agent_heartbeats(system_id, seen_at desc);

alter table public.security_events enable row level security;
alter table public.incidents enable row level security;
alter table public.agent_heartbeats enable row level security;

-- Only the server key is allowed to read/write these tables directly.
grant select, insert, update, delete on table public.security_events to service_role;
grant select, insert, update, delete on table public.incidents to service_role;
grant select, insert, update, delete on table public.agent_heartbeats to service_role;

-- Recreate ingest functions in a SECURITY DEFINER context so the agent can
-- use only the one-time per-system token and the public/anonymous key.

drop function if exists public.ingest_security_event(text, timestamptz, text, text, text, double precision, inet, integer, integer, text, text, text, jsonb);
create or replace function public.ingest_security_event(
    p_ingest_token text,
    p_event_time timestamptz,
    p_event_type text,
    p_attack_type text,
    p_severity text,
    p_confidence double precision,
    p_source_ip inet,
    p_source_port integer,
    p_dest_port integer,
    p_protocol text,
    p_evidence text,
    p_detected_by text,
    p_raw_data jsonb
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
    v_system_id uuid;
    v_event_id uuid := gen_random_uuid();
    v_incident_id uuid;
    v_company text;
    v_existing_count integer;
    v_cutoff timestamptz := now() - interval '15 minutes';
begin
    select id, company
      into v_system_id, v_company
      from public.systems
     where ingest_token_hash = encode(digest(p_ingest_token, 'sha256'), 'hex')
       and agent_enabled = true
     limit 1;

    if v_system_id is null then
        raise exception 'Invalid GuardianEye ingest token';
    end if;

    insert into public.security_events (
        id, system_id, event_time, event_type, attack_type, severity,
        confidence, source_ip, source_port, dest_port, protocol,
        evidence, status, detected_by, raw_data
    ) values (
        v_event_id, v_system_id, coalesce(p_event_time, now()),
        coalesce(p_event_type, 'security_detection'),
        coalesce(p_attack_type, 'Suspicious Activity'),
        coalesce(p_severity, 'Medium'),
        coalesce(p_confidence, 0.5), p_source_ip, p_source_port,
        p_dest_port, p_protocol, p_evidence, 'Open', p_detected_by,
        coalesce(p_raw_data, '{}'::jsonb)
    );

    select id, event_count
      into v_incident_id, v_existing_count
      from public.incidents
     where system_id = v_system_id
       and attack_type = coalesce(p_attack_type, 'Suspicious Activity')
       and status = 'Open'
       and last_seen >= v_cutoff
       and (p_source_ip is null or source_ip = p_source_ip)
     order by last_seen desc
     limit 1;

    if v_incident_id is not null then
        update public.incidents
           set last_seen = coalesce(p_event_time, now()),
               event_count = coalesce(event_count, 0) + 1,
               severity = coalesce(p_severity, severity),
               evidence_summary = left(
                   concat_ws(' | ', evidence_summary, p_evidence),
                   1200
               )
         where id = v_incident_id;
    else
        v_incident_id := gen_random_uuid();
        insert into public.incidents (
            id, system_id, title, attack_type, severity, source_ip,
            first_seen, last_seen, event_count, status, evidence_summary
        ) values (
            v_incident_id,
            v_system_id,
            coalesce(p_attack_type, 'Suspicious Activity') || ' detected on ' || coalesce(v_company, 'system'),
            coalesce(p_attack_type, 'Suspicious Activity'),
            coalesce(p_severity, 'Medium'),
            p_source_ip,
            coalesce(p_event_time, now()),
            coalesce(p_event_time, now()),
            1,
            'Open',
            left(coalesce(p_evidence, ''), 1200)
        );
    end if;

    return json_build_object(
        'ok', true,
        'system_id', v_system_id,
        'event_id', v_event_id,
        'incident_id', v_incident_id
    );
end;
$$;

drop function if exists public.ingest_agent_heartbeat(text, text, text, text, double precision, double precision, integer, jsonb);
create or replace function public.ingest_agent_heartbeat(
    p_ingest_token text,
    p_hostname text,
    p_os_name text,
    p_agent_version text,
    p_cpu_percent double precision,
    p_memory_percent double precision,
    p_open_connections integer,
    p_monitored_logs jsonb
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
    v_system_id uuid;
    v_id uuid := gen_random_uuid();
begin
    select id into v_system_id
      from public.systems
     where ingest_token_hash = encode(digest(p_ingest_token, 'sha256'), 'hex')
       and agent_enabled = true
     limit 1;

    if v_system_id is null then
        raise exception 'Invalid GuardianEye ingest token';
    end if;

    insert into public.agent_heartbeats (
        id, system_id, seen_at, hostname, os_name, agent_version,
        cpu_percent, memory_percent, open_connections, monitored_logs
    ) values (
        v_id, v_system_id, now(), p_hostname, p_os_name, p_agent_version,
        p_cpu_percent, p_memory_percent, p_open_connections, p_monitored_logs
    );

    update public.systems
       set agent_last_seen = now()
     where id = v_system_id;

    return json_build_object('ok', true, 'system_id', v_system_id, 'heartbeat_id', v_id);
end;
$$;

grant execute on function public.ingest_security_event(text, timestamptz, text, text, text, double precision, inet, integer, integer, text, text, text, jsonb) to anon;
grant execute on function public.ingest_agent_heartbeat(text, text, text, text, double precision, double precision, integer, jsonb) to anon;

-- Make sure the public API cannot read the sensitive tables directly.
revoke all on table public.security_events from anon, authenticated;
revoke all on table public.incidents from anon, authenticated;
revoke all on table public.agent_heartbeats from anon, authenticated;
