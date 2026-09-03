-- ============================================================
-- MDP DATA - COMPLETE DATABASE SCHEMA (FINAL)
-- ============================================================
-- For a NEW Supabase project.
-- Final permission logic:
--   Brand permission AND Partner permission
-- ============================================================

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

create table if not exists public.brands (
  id bigserial primary key,
  name text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists public.partners (
  id bigserial primary key,
  name text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists public.permissions (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  perm_type text not null check (perm_type in ('brand','partner')),
  value text not null,
  created_at timestamptz not null default now(),
  unique(user_id, perm_type, value)
);
create index if not exists permissions_user_type_idx
on public.permissions(user_id, perm_type);

create table if not exists public.data_rows (
  id bigserial primary key,
  brand text not null,
  partner text not null,
  row_data jsonb not null,
  uploaded_at timestamptz not null default now()
);
create index if not exists data_rows_brand_idx on public.data_rows(brand);
create index if not exists data_rows_partner_idx on public.data_rows(partner);
create index if not exists data_rows_brand_partner_idx on public.data_rows(brand, partner);

create table if not exists public.data_columns (
  id int primary key default 1,
  columns jsonb not null,
  brand_col_index int not null default 4,
  partner_col_index int not null default 2,
  updated_at timestamptz not null default now(),
  constraint data_columns_single_row check(id = 1)
);

create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = auth.uid()),
    false
  );
$$;

alter table public.profiles enable row level security;
alter table public.brands enable row level security;
alter table public.partners enable row level security;
alter table public.permissions enable row level security;
alter table public.data_rows enable row level security;
alter table public.data_columns enable row level security;

-- Remove every existing policy on project tables.
do $$
declare tbl text; pol record;
begin
  foreach tbl in array array['profiles','brands','partners','permissions','data_rows','data_columns']
  loop
    for pol in select policyname from pg_policies
      where schemaname='public' and tablename=tbl
    loop
      execute format('drop policy if exists %I on public.%I', pol.policyname, tbl);
    end loop;
  end loop;
end $$;

-- PROFILES
create policy "profiles_select_own_or_admin" on public.profiles
for select to authenticated
using (id = auth.uid() or public.is_admin());

create policy "profiles_update_admin" on public.profiles
for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- BRANDS
create policy "brands_select_authenticated" on public.brands
for select to authenticated using (true);
create policy "brands_insert_admin" on public.brands
for insert to authenticated with check (public.is_admin());
create policy "brands_update_admin" on public.brands
for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "brands_delete_admin" on public.brands
for delete to authenticated using (public.is_admin());

-- PARTNERS
create policy "partners_select_authenticated" on public.partners
for select to authenticated using (true);
create policy "partners_insert_admin" on public.partners
for insert to authenticated with check (public.is_admin());
create policy "partners_update_admin" on public.partners
for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "partners_delete_admin" on public.partners
for delete to authenticated using (public.is_admin());

-- PERMISSIONS
create policy "permissions_select_own_or_admin" on public.permissions
for select to authenticated
using (user_id = auth.uid() or public.is_admin());
create policy "permissions_insert_admin" on public.permissions
for insert to authenticated with check (public.is_admin());
create policy "permissions_update_admin" on public.permissions
for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "permissions_delete_admin" on public.permissions
for delete to authenticated using (public.is_admin());

-- DATA ROWS - FINAL EXCEL STYLE FILTER
-- User sees a row only when:
-- matching Brand permission
-- AND
-- matching Partner permission
create policy "data_rows_exact_excel_filter" on public.data_rows
for select to authenticated
using (
  public.is_admin()
  or (
    exists (
      select 1 from public.permissions b
      where b.user_id = auth.uid()
        and b.perm_type = 'brand'
        and b.value = public.data_rows.brand
    )
    and exists (
      select 1 from public.permissions p
      where p.user_id = auth.uid()
        and p.perm_type = 'partner'
        and p.value = public.data_rows.partner
    )
  )
);

create policy "data_rows_admin_insert" on public.data_rows
for insert to authenticated with check (public.is_admin());
create policy "data_rows_admin_update" on public.data_rows
for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "data_rows_admin_delete" on public.data_rows
for delete to authenticated using (public.is_admin());

-- DATA COLUMNS
create policy "data_columns_select_authenticated" on public.data_columns
for select to authenticated using (true);
create policy "data_columns_insert_admin" on public.data_columns
for insert to authenticated with check (public.is_admin());
create policy "data_columns_update_admin" on public.data_columns
for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "data_columns_delete_admin" on public.data_columns
for delete to authenticated using (public.is_admin());

-- Grants (RLS still enforces row security)
grant usage on schema public to authenticated;
grant select, insert, update, delete
on public.profiles, public.brands, public.partners,
   public.permissions, public.data_rows, public.data_columns
to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Verification
select tablename, policyname, cmd
from pg_policies
where schemaname='public'
and tablename in ('profiles','brands','partners','permissions','data_rows','data_columns')
order by tablename, policyname;

-- AFTER SETUP:
-- Create first user, then run:
-- update public.profiles
-- set is_admin = true
-- where email = 'YOUR_EMAIL@mdp.local';
