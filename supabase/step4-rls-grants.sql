-- 4단계 제안 SQL 2: 메모 테이블(public.defense_notes)의 RLS와 최소 권한. 다른 테이블은 건드리지 않습니다.
-- 검토한 뒤 Supabase 대시보드 > SQL Editor에서 실행하세요. 메모·이메일·키는 들어 있지 않습니다.
--
-- ※ SQL Editor는 마지막 결과 표만 보여 줍니다. 아래 ①②③을 한 블록씩 따로 선택해서(드래그) Run 하세요.
-- ※ 서버 API는 service_role 키로 이 테이블을 읽고 씁니다. service_role은 이 SQL이 건드리지 않고 RLS를 우회하므로
--    앱 API 동작은 그대로이고, 소유자 검사는 API 코드(src/notes-service.mjs)가 맡습니다.
--    이 SQL은 anon·authenticated 키로 Supabase Data API를 직접 부르는 경로를 막기 위한 두 번째 방어선입니다.

-- ===== ① 적용 전: 두 역할의 실제 권한 =====
select 'before' as phase, r.role_name, p.privilege,
       has_table_privilege(r.role_name, 'public.defense_notes', p.privilege) as granted
from (values ('anon'), ('authenticated')) as r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as p(privilege)
order by r.role_name, p.privilege;

select 'before' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'defense_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

-- ===== ② 적용 =====
begin;

alter table public.defense_notes enable row level security;

-- 기존 권한부터 모두 회수합니다.
revoke all on table public.defense_notes from public, anon, authenticated;

-- authenticated에는 네 가지만 줍니다. (anon에는 아무것도 주지 않습니다)
grant select, insert, update, delete on table public.defense_notes to authenticated;

-- 여러 번 실행해도 같은 결과가 되도록 같은 이름의 정책을 먼저 지웁니다.
drop policy if exists defense_notes_select_own on public.defense_notes;
drop policy if exists defense_notes_insert_own on public.defense_notes;
drop policy if exists defense_notes_update_own on public.defense_notes;
drop policy if exists defense_notes_delete_own on public.defense_notes;

-- SELECT: 기존 행의 owner_id가 로그인한 사용자일 때만 읽습니다.
create policy defense_notes_select_own on public.defense_notes
  for select to authenticated
  using ((select auth.uid()) = owner_id);

-- INSERT: 새 행의 owner_id가 로그인한 사용자일 때만 넣습니다.
create policy defense_notes_insert_own on public.defense_notes
  for insert to authenticated
  with check ((select auth.uid()) = owner_id);

-- UPDATE: 기존 행(USING)과 바뀐 새 행(WITH CHECK)의 owner_id가 모두 로그인한 사용자여야 합니다.
create policy defense_notes_update_own on public.defense_notes
  for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

-- DELETE: 기존 행의 owner_id가 로그인한 사용자일 때만 지웁니다.
create policy defense_notes_delete_own on public.defense_notes
  for delete to authenticated
  using ((select auth.uid()) = owner_id);

commit;

-- ===== ③ 적용 후: 같은 질문으로 다시 대조 =====
-- 정상: anon은 네 가지 모두 granted = false, authenticated는 네 가지 모두 granted = true
select 'after' as phase, r.role_name, p.privilege,
       has_table_privilege(r.role_name, 'public.defense_notes', p.privilege) as granted
from (values ('anon'), ('authenticated')) as r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as p(privilege)
order by r.role_name, p.privilege;

-- 정상: anon 행은 없고, authenticated에는 DELETE, INSERT, SELECT, UPDATE 네 줄만 있습니다. (TRUNCATE·REFERENCES·TRIGGER 없음)
select 'after' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'defense_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

-- 정상: RLS 켜짐, 정책 네 개(select·insert·update·delete)
select c.relrowsecurity as rls_enabled,
       (select string_agg(cmd, ',' order by cmd) from pg_policies
         where schemaname = 'public' and tablename = 'defense_notes') as policy_commands
from pg_class c where c.oid = 'public.defense_notes'::regclass;
