-- 11단계: 기기 승인 상태를 저장하는 비공개 표입니다. 서버(service role)만 읽고 쓰며, 브라우저의 공개 키 요청으로는 접근할 수 없습니다.
-- 승인(pending → approved)과 해제(→ revoked)는 운영 측이 이 표에서만 바꿉니다. 앱 화면과 API에는 승인하는 길이 없습니다.
-- 이 파일에는 비밀번호·토큰·기기 핸들 원문이 없습니다(표에는 핸들의 SHA-256 지문만 저장됩니다).
-- 실행: Supabase SQL Editor에서 ① → ② 순서로 블록 하나씩 Run 하세요.

-- ① 표 만들기 -------------------------------------------------------------
create table if not exists public.defense_devices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  handle_sha256 text not null unique check (handle_sha256 ~ '^[0-9a-f]{64}$'),
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz
);
alter table public.defense_devices enable row level security;
revoke all on public.defense_devices from anon, authenticated;

-- ② 확인(읽기만 합니다): RLS가 켜져 있고 anon·authenticated 권한이 모두 false여야 합니다 -----------
select c.relrowsecurity as rls_on,
       has_table_privilege('anon', 'public.defense_devices', 'select') as anon_select,
       has_table_privilege('authenticated', 'public.defense_devices', 'select') as authenticated_select
from pg_class c where c.oid = 'public.defense_devices'::regclass;

-- 승인·해제(운영 측만, 필요할 때): 승인 요청 화면에 나온 deviceId(또는 아래 목록의 id)를 확인한 뒤 실행합니다 --------
-- select id, owner_id, status, requested_at from public.defense_devices order by requested_at desc;
-- update public.defense_devices set status = 'approved', decided_at = now() where id = '<deviceId>';
-- update public.defense_devices set status = 'revoked',  decided_at = now() where id = '<deviceId>';

-- 되돌리기(필요할 때만): drop table if exists public.defense_devices;
