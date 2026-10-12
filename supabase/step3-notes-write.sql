-- 3단계: 로그인한 사용자가 메모를 추가할 수 있게 테이블을 보강합니다.
-- Supabase 대시보드 > SQL Editor에 통째로 붙여넣고 Run 하세요. 여러 번 실행해도 안전합니다.
-- 이 파일에는 메모 본문도 키 값도 없습니다.

-- 새 메모는 position을 지정하지 않으므로 기본값을 둡니다. (목록은 position, created_at 순으로 정렬)
alter table public.defense_notes alter column position set default 0;

-- owner_id는 서버가 확인한 사용자 ID로 채웁니다. auth.users 외래키는 여전히 걸지 않습니다.
create index if not exists defense_notes_owner_id_idx on public.defense_notes (owner_id);

-- RLS와 권한은 2단계 그대로입니다. 한 번 더 확실히 해 둡니다: 서버 전용 키(service_role)만 접근합니다.
alter table public.defense_notes enable row level security;
revoke all on table public.defense_notes from public, anon, authenticated;
grant select, insert, update, delete on table public.defense_notes to service_role;

-- 실행 뒤 확인용 (정상: rls_enabled true, anon·authenticated 모두 false, position_default 0, service_role_insert true)
select
  (select relrowsecurity from pg_class where oid = 'public.defense_notes'::regclass) as rls_enabled,
  has_table_privilege('anon', 'public.defense_notes', 'select,insert,update,delete')          as anon_any,
  has_table_privilege('authenticated', 'public.defense_notes', 'select,insert,update,delete') as authenticated_any,
  has_table_privilege('service_role', 'public.defense_notes', 'insert')                       as service_role_insert,
  (select column_default from information_schema.columns
    where table_schema = 'public' and table_name = 'defense_notes' and column_name = 'position') as position_default;
