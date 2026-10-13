-- 8단계 제안 SQL: 자료의 구역 열(zone)을 추가합니다. 검토한 뒤 Supabase 대시보드 > SQL Editor에서 실행하세요.
-- 메모·이메일·키는 들어 있지 않습니다. 여러 번 실행해도 안전합니다. 이 SQL을 실행하기 전에도 앱은 동작합니다
-- (구역 열이 없으면 서버가 모든 행을 개인 메모로 봅니다).
--
-- ※ SQL Editor는 마지막 결과 표만 보여 줍니다. ①②③을 한 블록씩 따로 선택해서 Run 하세요.
-- ※ 서버 API는 service_role 키로 읽고 쓰므로 anon·authenticated 권한은 건드리지 않습니다(5단계 상태 유지).

-- ===== ① 적용 전 =====
select column_name, data_type, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'defense_notes' order by ordinal_position;

-- ===== ② 적용 =====
alter table public.defense_notes
  add column if not exists zone text not null default 'note';
alter table public.defense_notes drop constraint if exists defense_notes_zone_check;
alter table public.defense_notes
  add constraint defense_notes_zone_check check (zone in ('note', 'notice'));

-- 공개 가능한 가상 공지 한 건을 넣습니다. (이미 있으면 넣지 않습니다. 소유자는 비워 두며, 수정은 강사만 됩니다)
insert into public.defense_notes (owner_id, zone, position, title, content)
select null, 'notice', 1, '강사 공지 (가상)', '공개 가능한 가상 공지입니다. 일반 학생은 읽기만 할 수 있습니다.'
where not exists (select 1 from public.defense_notes where zone = 'notice' and title = '강사 공지 (가상)');

-- ===== ③ 적용 후: 정상은 note 5건(기존 행), notice 1건이고 anon·authenticated 권한은 둘 다 false입니다 =====
select zone, count(*) from public.defense_notes group by zone order by zone;
select has_table_privilege('anon', 'public.defense_notes', 'SELECT') as anon_select,
       has_table_privilege('authenticated', 'public.defense_notes', 'SELECT') as authenticated_select;
