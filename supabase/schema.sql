-- PinIt database: shared lists, their items, who is on each list, and display names.
-- Run once in a new Supabase project (SQL editor, or through the Supabase connector).
-- Safe to run again: everything is created only if missing or replaced in place.
--
-- Model
--   A list is visible only to its members. The person who creates it is the owner and first member.
--   Anyone who has the list's id (it travels in the invite link, and is random) can join:
--   as an editor on a shared list, or as a viewer on a public, view-only list such as a guide.
--   Members read through row level security. All writes go through the functions below,
--   which check membership themselves, so there are no direct insert/update/delete rights.

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  name text not null default '' check (char_length(name) <= 60),
  updated_at timestamptz not null default now()
);

create table if not exists public.lists (
  id text primary key check (id ~ '^[a-z0-9]{12,40}$'),
  owner uuid not null references auth.users (id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists public.list_members (
  list_id text not null references public.lists (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null default 'editor' check (role in ('editor', 'viewer')),
  joined_at timestamptz not null default now(),
  primary key (list_id, user_id)
);
alter table public.list_members add column if not exists role text not null default 'editor' check (role in ('editor', 'viewer'));

create table if not exists public.items (
  list_id text not null references public.lists (id) on delete cascade,
  id text not null check (id ~ '^[A-Za-z0-9_-]{1,64}$'),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  -- What the item is, independent of the list it sits in: a Google place id, or a film or book id.
  key text generated always as (coalesce(nullif(data->>'placeId', ''), nullif(data->>'extId', ''))) stored,
  primary key (list_id, id)
);
create index if not exists items_key_idx on public.items (key) where key is not null;

create index if not exists list_members_user_idx on public.list_members (user_id);

alter table public.profiles enable row level security;
alter table public.lists enable row level security;
alter table public.list_members enable row level security;
alter table public.items enable row level security;

-- Membership checks run as the function owner so the policies below don't recurse.
create or replace function public.is_member(p_list text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from list_members where list_id = p_list and user_id = auth.uid());
$$;

create or replace function public.can_edit(p_list text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from list_members where list_id = p_list and user_id = auth.uid() and role = 'editor');
$$;

create or replace function public.shares_list_with(p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from list_members mine join list_members theirs on theirs.list_id = mine.list_id
    where mine.user_id = auth.uid() and theirs.user_id = p_user);
$$;

drop policy if exists "members read lists" on public.lists;
create policy "members read lists" on public.lists for select to authenticated using (public.is_member(id));

drop policy if exists "members read items" on public.items;
create policy "members read items" on public.items for select to authenticated using (public.is_member(list_id));

drop policy if exists "members read membership" on public.list_members;
create policy "members read membership" on public.list_members for select to authenticated using (public.is_member(list_id));

drop policy if exists "read names of people on my lists" on public.profiles;
create policy "read names of people on my lists" on public.profiles for select to authenticated
  using (id = auth.uid() or public.shares_list_with(id));

revoke all on public.profiles, public.lists, public.list_members, public.items from anon, authenticated;
grant select on public.profiles, public.lists, public.list_members, public.items to authenticated;

-- ---------- writes ----------

create or replace function public.put_list(p_id text, p_data jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if pg_column_size(p_data) > 200000 then raise exception 'list too large'; end if;
  if exists (select 1 from lists where id = p_id) then
    if not can_edit(p_id) then raise exception 'not allowed to change this list'; end if;
    update lists set data = p_data, updated_at = now() where id = p_id;
  else
    insert into lists (id, owner, data) values (p_id, auth.uid(), p_data);
    insert into list_members (list_id, user_id) values (p_id, auth.uid());
  end if;
end $$;

create or replace function public.put_item(p_list text, p_id text, p_data jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not can_edit(p_list) then raise exception 'not allowed to change this list'; end if;
  if pg_column_size(p_data) > 600000 then raise exception 'item too large'; end if;
  if not exists (select 1 from items where list_id = p_list and id = p_id)
     and (select count(*) from items where list_id = p_list) >= 1000 then
    raise exception 'list is full';
  end if;
  insert into items (list_id, id, data) values (p_list, p_id, p_data)
  on conflict (list_id, id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function public.delete_item(p_list text, p_id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not can_edit(p_list) then raise exception 'not allowed to change this list'; end if;
  delete from items where list_id = p_list and id = p_id;
end $$;

-- Only the owner can delete a list. Its items and memberships go with it.
create or replace function public.delete_list(p_id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from lists where id = p_id and owner = auth.uid()) then
    raise exception 'only the owner can delete a list';
  end if;
  delete from lists where id = p_id;
end $$;

-- Joining needs the list id from an invite link, and, for a list people add to, a display name.
-- People who join a public list can look but not change it, and need no name.
create or replace function public.join_list(p_id text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if not exists (select 1 from lists where id = p_id) then return false; end if;
  if exists (select 1 from lists where id = p_id and coalesce(data->>'vis', '') <> 'public')
     and not exists (select 1 from profiles where id = auth.uid() and btrim(name) <> '') then
    raise exception 'add your name before joining';
  end if;
  insert into list_members (list_id, user_id, role)
  select l.id, auth.uid(), case when l.data->>'vis' = 'public' then 'viewer' else 'editor' end from lists l where l.id = p_id
  on conflict do nothing;
  return true;
end $$;

-- What an invite link opens: the list's name, type and whether it is view only. Nothing else.
create or replace function public.list_preview(p_id text) returns table (name text, type text, vis text)
language sql stable security definer set search_path = public as $$
  select left(coalesce(data->>'name', ''), 80), coalesce(data->>'type', ''), coalesce(data->>'vis', '') from lists where id = p_id;
$$;

-- The owner stays on their own list; they delete it instead.
create or replace function public.leave_list(p_id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from list_members m using lists l
  where m.list_id = p_id and m.user_id = auth.uid() and l.id = m.list_id and l.owner <> auth.uid();
end $$;

create or replace function public.set_name(p_name text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  insert into profiles (id, name) values (auth.uid(), left(coalesce(p_name, ''), 60))
  on conflict (id) do update set name = excluded.name, updated_at = now();
end $$;

-- How many shared lists of each type include an item. Counts only: no list names, owners or contents.
create or replace function public.item_stats(p_keys text[]) returns table (key text, list_type text, n bigint)
language sql stable security definer set search_path = public as $$
  select i.key, coalesce(l.data->>'type', 'guide'), count(distinct i.list_id)
  from items i join lists l on l.id = i.list_id
  where i.key = any (p_keys[1:50])
  group by 1, 2;
$$;

revoke all on function public.can_edit(text), public.item_stats(text[]), public.list_preview(text) from public, anon;
grant execute on function public.can_edit(text), public.item_stats(text[]), public.list_preview(text) to authenticated;

revoke all on function public.is_member(text), public.shares_list_with(uuid), public.put_list(text, jsonb),
  public.put_item(text, text, jsonb), public.delete_item(text, text), public.delete_list(text),
  public.join_list(text), public.leave_list(text), public.set_name(text) from public, anon;
grant execute on function public.is_member(text), public.shares_list_with(uuid), public.put_list(text, jsonb),
  public.put_item(text, text, jsonb), public.delete_item(text, text), public.delete_list(text),
  public.join_list(text), public.leave_list(text), public.set_name(text) to authenticated;

-- ---------- live updates ----------
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['lists', 'items', 'list_members', 'profiles'] loop
      if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;

-- ---------- photos ----------
-- Photos are resized and stripped of location data in the browser before upload.
-- The bucket is public: a photo opens for anyone who has its address, which is random.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', true, 2097152, array['image/jpeg'])
on conflict (id) do update set public = excluded.public, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "signed-in people add photos" on storage.objects;
create policy "signed-in people add photos" on storage.objects for insert to authenticated with check (bucket_id = 'photos');
