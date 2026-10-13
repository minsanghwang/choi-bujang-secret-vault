-- 10단계: 비공개 가상 메모 사본과 복원 감사 기록. Supabase 대시보드 → SQL Editor → New query에서 ①→②→③→④ 순서로 하나씩 Run 하세요.
-- 서버 함수만(service_role) 읽고 씁니다. 화면·anon·로그인 사용자는 이 표를 읽거나 바꿀 수 없습니다.

-- ① 먼저 확인(읽기만): 두 표가 아직 없어야 합니다.
select table_name from information_schema.tables
where table_schema = 'public' and table_name in ('defense_notes_backup', 'defense_restore_audit');

-- ② 표 만들기와 잠금
create table if not exists public.defense_notes_backup (
  backup_id uuid primary key default gen_random_uuid(),
  note_id uuid not null,
  owner_id uuid not null,
  position bigint,
  title text not null,
  content text not null,
  note_created_at timestamptz,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at timestamptz not null default now(),
  unique (note_id, content_sha256)
);
alter table public.defense_notes_backup enable row level security;
revoke all on public.defense_notes_backup from anon, authenticated;

create table if not exists public.defense_restore_audit (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  actor uuid,
  note_id uuid,
  outcome text not null,
  reason text
);
alter table public.defense_restore_audit enable row level security;
revoke all on public.defense_restore_audit from anon, authenticated;
-- 감사 기록은 덧붙이기만 합니다. 서버 키로도 고치거나 지울 수 없게 막습니다.
create or replace function public.defense_restore_audit_append_only() returns trigger
language plpgsql as $$ begin raise exception 'defense_restore_audit is append-only'; end $$;
drop trigger if exists defense_restore_audit_no_change on public.defense_restore_audit;
create trigger defense_restore_audit_no_change before update or delete or truncate on public.defense_restore_audit
  for each statement execute function public.defense_restore_audit_append_only();

-- ③ 지금의 개인 메모(구역 note, 주인 있음)를 사전 백업으로 복사합니다. 같은 내용은 두 번 들어가지 않습니다.
insert into public.defense_notes_backup (note_id, owner_id, position, title, content, note_created_at, content_sha256)
select n.id, n.owner_id, n.position, n.title, n.content, n.created_at,
       encode(sha256(convert_to(n.title, 'UTF8') || '\x00'::bytea || convert_to(n.content, 'UTF8')), 'hex')
from public.defense_notes n
where n.owner_id is not null and n.zone = 'note'
on conflict (note_id, content_sha256) do nothing;

-- ④ 사전 백업을 다시 읽어 검증합니다. ok_rows와 total이 같아야 하고, 두 표 모두 anon·authenticated 권한이 false여야 합니다.
select count(*) as total,
       count(*) filter (where content_sha256 = encode(sha256(convert_to(title, 'UTF8') || '\x00'::bytea || convert_to(content, 'UTF8')), 'hex')) as ok_rows
from public.defense_notes_backup;
select has_table_privilege('anon', 'public.defense_notes_backup', 'select') as anon_backup,
       has_table_privilege('authenticated', 'public.defense_notes_backup', 'select') as auth_backup,
       has_table_privilege('anon', 'public.defense_restore_audit', 'select') as anon_audit,
       has_table_privilege('authenticated', 'public.defense_restore_audit', 'select') as auth_audit;
