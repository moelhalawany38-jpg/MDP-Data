
-- MDP Data: تحويل الصلاحيات إلى صلاحيات مركبة Brand + Partner
-- شغّل هذا الملف مرة واحدة في Supabase SQL Editor.

create table if not exists public.user_permissions (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  brand text not null,
  partner_name text not null,
  created_at timestamptz not null default now(),
  unique (user_id, brand, partner_name)
);

create index if not exists user_permissions_user_idx
  on public.user_permissions(user_id);

alter table public.user_permissions enable row level security;

drop policy if exists "compound_permissions_select_own_or_admin" on public.user_permissions;
create policy "compound_permissions_select_own_or_admin"
on public.user_permissions
for select
using (user_id = auth.uid() or public.is_admin());

drop policy if exists "compound_permissions_insert_admin" on public.user_permissions;
create policy "compound_permissions_insert_admin"
on public.user_permissions
for insert
with check (public.is_admin());

drop policy if exists "compound_permissions_delete_admin" on public.user_permissions;
create policy "compound_permissions_delete_admin"
on public.user_permissions
for delete
using (public.is_admin());

-- استبدال سياسة قراءة البيانات القديمة بسياسة الصلاحيات المركبة.
drop policy if exists "data_select_permitted_or_admin" on public.data_rows;
drop policy if exists "data_select_compound_permission_or_admin" on public.data_rows;

create policy "data_select_compound_permission_or_admin"
on public.data_rows
for select
using (
  public.is_admin()
  or exists (
    select 1
    from public.user_permissions up
    where up.user_id = auth.uid()
      and lower(trim(up.brand)) = lower(trim(data_rows.brand))
      and lower(trim(up.partner_name)) = lower(trim(data_rows.partner))
  )
);
