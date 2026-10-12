-- 5단계 제안 SQL: 메모 테이블(public.defense_notes)의 직접 접근 권한을 거둡니다. 다른 테이블은 건드리지 않습니다.
-- 검토한 뒤 Supabase 대시보드 > SQL Editor에서 실행하세요. 메모·이메일·키는 들어 있지 않습니다.
--
-- 목적: 브라우저가 가진 공개 키(anon)나 로그인 토큰(authenticated)으로 Supabase Data API를 직접 불러
--       메모를 읽거나 고치는 길을 닫습니다. 메모는 Vercel 서버 함수(/api/notes)만 service_role 키로 다룹니다.
-- ※ service_role의 권한은 건드리지 않으므로 서버 함수(로그인·소유자 검사 포함)는 그대로 동작합니다.
-- ※ supabase/step4-rls-grants.sql의 ②(authenticated에 GRANT)는 이 SQL과 반대 방향이니 실행하지 마세요.
--    이미 실행했다면 이 SQL을 그 뒤에 실행하면 다시 닫힙니다.
-- ※ SQL Editor는 마지막 결과 표만 보여 줍니다. ①②③을 한 블록씩 따로 선택해서 Run 하세요.

-- ===== ① 적용 전: 두 역할의 실제 권한 (두 쿼리를 따로 실행) =====
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

-- ===== ② 적용: 직접 권한 회수 한 묶음 =====
begin;

revoke all on table public.defense_notes from public, anon, authenticated;

-- 서버 함수가 쓰는 service_role은 읽기·추가·수정·삭제를 그대로 유지합니다.
grant select, insert, update, delete on table public.defense_notes to service_role;

-- RLS는 켜 둡니다. 정책이 없으므로 service_role 외에는 어떤 행도 볼 수 없습니다.
alter table public.defense_notes enable row level security;

commit;

-- ===== ③ 적용 후: 같은 질문으로 다시 대조 (두 쿼리를 따로 실행) =====
-- 정상: anon과 authenticated 모두 SELECT·INSERT·UPDATE·DELETE가 granted = false
select 'after' as phase, r.role_name, p.privilege,
       has_table_privilege(r.role_name, 'public.defense_notes', p.privilege) as granted
from (values ('anon'), ('authenticated'), ('service_role')) as r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) as p(privilege)
order by r.role_name, p.privilege;

-- 정상: 결과가 0행 (PUBLIC·anon·authenticated 줄이 없음). RLS는 켜짐.
select 'after' as phase, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'defense_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;
