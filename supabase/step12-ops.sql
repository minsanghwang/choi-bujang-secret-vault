-- 12단계: 탈환 작전실이 읽는 "가린 서버 기록" 표입니다. 자료 API가 응답한 결과의 메타데이터만 남깁니다.
-- 남기는 것: 시각, 요청 ID, 메서드, 경로 이름(:id 형태), 응답 상태, 거부 이유 코드, 인증 방식, 사용자의 가명(해시 12자).
-- 남기지 않는 것: 사용자 ID 원문, 이메일, 토큰, 쿠키, 요청·응답 본문, 메모 제목·내용, 쿼리 문자열.
-- 최근 2000건만 보관하는 순환 기록이며(오래된 줄은 새 줄이 들어올 때 지워짐), 서버(service role)만 읽고 씁니다.
-- 이 파일에는 비밀번호·토큰·메모 내용이 없습니다. 실행: Supabase SQL Editor에서 ① → ② 순서로 블록 하나씩 Run 하세요.

-- ① 표·권한·순환 규칙 ---------------------------------------------------------
create table if not exists public.defense_ops_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  request_id uuid not null,
  method text not null check (method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OTHER')),
  route text not null check (route ~ '^[a-z]{1,16}(/:id)?$'),
  status integer not null check (status between 100 and 599),
  reason text check (reason is null or reason ~ '^[a-z0-9_]{1,40}$'),
  auth text not null check (auth in ('bearer', 'cookie', 'none')),
  actor text check (actor is null or actor ~ '^[0-9a-f]{12}$')
);
create index if not exists defense_ops_log_at_idx on public.defense_ops_log (at desc);
create index if not exists defense_ops_log_request_idx on public.defense_ops_log (request_id);
alter table public.defense_ops_log enable row level security;
revoke all on public.defense_ops_log from anon, authenticated;

create or replace function public.defense_ops_log_prune()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.defense_ops_log where id <= new.id - 2000;
  return null;
end;
$$;
revoke all on function public.defense_ops_log_prune() from public, anon, authenticated;
drop trigger if exists defense_ops_log_prune_trigger on public.defense_ops_log;
create trigger defense_ops_log_prune_trigger after insert on public.defense_ops_log
  for each row execute function public.defense_ops_log_prune();

-- ② 확인(읽기만 합니다): RLS가 켜져 있고 anon·authenticated 권한이 모두 false여야 합니다 ------------------
select c.relrowsecurity as rls_on,
       has_table_privilege('anon', 'public.defense_ops_log', 'select') as anon_select,
       has_table_privilege('authenticated', 'public.defense_ops_log', 'select') as authenticated_select,
       (select count(*) from public.defense_ops_log) as rows
from pg_class c where c.oid = 'public.defense_ops_log'::regclass;

-- 되돌리기(필요할 때만): drop table if exists public.defense_ops_log; drop function if exists public.defense_ops_log_prune();
