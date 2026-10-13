-- 10단계 보강: 메모를 만들거나 고치거나 지우기 "직전의 값"을 비공개 사본 표에 자동으로 남깁니다.
-- 그래서 나중에 만든 메모도 변조 전 값으로 복원할 수 있습니다. (앱 코드와 3~8단계 쓰기 경로는 바꾸지 않습니다.)
-- 해시 규칙은 서버와 같습니다: sha256(UTF-8(제목) + 0x00 + UTF-8(내용)), 소문자 16진수.
-- 실행: Supabase SQL Editor에서 ① → ② 순서로 블록 하나씩 Run 하세요. 되돌리려면 맨 아래 "되돌리기"만 실행합니다.
-- 이 파일에는 비밀번호·토큰·메모 내용이 없습니다.

-- ① 함수와 트리거 만들기 -------------------------------------------------
create or replace function public.defense_notes_snapshot()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  r public.defense_notes;
begin
  -- 만들 때는 새 값, 고치거나 지울 때는 바뀌기 직전의 값을 남깁니다.
  if tg_op = 'INSERT' then r := new; else r := old; end if;
  begin
    if r.owner_id is not null and r.zone = 'note' then
      insert into public.defense_notes_backup (note_id, owner_id, position, title, content, note_created_at, content_sha256)
      values (r.id, r.owner_id, r.position, coalesce(r.title, ''), coalesce(r.content, ''), r.created_at,
        encode(extensions.digest(convert_to(coalesce(r.title, ''), 'UTF8') || '\x00'::bytea || convert_to(coalesce(r.content, ''), 'UTF8'), 'sha256'), 'hex'))
      on conflict (note_id, content_sha256) do nothing;   -- 같은 값은 한 번만 남깁니다.
    end if;
  exception when others then
    -- 사본을 못 남겨도 사용자의 메모 쓰기는 막지 않습니다. 경고만 남깁니다.
    raise warning 'defense_notes_snapshot_failed';
  end;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

revoke all on function public.defense_notes_snapshot() from public, anon, authenticated;

drop trigger if exists defense_notes_snapshot_insert on public.defense_notes;
drop trigger if exists defense_notes_snapshot_change on public.defense_notes;
create trigger defense_notes_snapshot_insert after insert on public.defense_notes
  for each row execute function public.defense_notes_snapshot();
create trigger defense_notes_snapshot_change before update or delete on public.defense_notes
  for each row execute function public.defense_notes_snapshot();

-- ② 확인(읽기만 합니다): 트리거 2개가 켜져 있고 함수가 보안 정의자인지 ----------------
select t.tgname, t.tgenabled as enabled, p.prosecdef as security_definer
from pg_trigger t join pg_proc p on p.oid = t.tgfoid
where t.tgrelid = 'public.defense_notes'::regclass and not t.tgisinternal and p.proname = 'defense_notes_snapshot'
order by t.tgname;

-- 되돌리기(필요할 때만, 기존 사본 5건은 그대로 남습니다) ------------------------------
-- drop trigger if exists defense_notes_snapshot_insert on public.defense_notes;
-- drop trigger if exists defense_notes_snapshot_change on public.defense_notes;
-- drop function if exists public.defense_notes_snapshot();
