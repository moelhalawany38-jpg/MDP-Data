-- =========================================================
-- MDP DATA - ARCHIVE ADD-ON
-- Run ONCE in Supabase SQL Editor
-- =========================================================

create table if not exists public.archive_mdp_rows (
  id bigserial primary key,
  brand text not null,
  partner text not null,
  customer_name text,
  customer_code text,
  value numeric not null default 0,
  month text not null,
  uploaded_at timestamptz not null default now()
);

create index if not exists archive_mdp_brand_partner_idx
on public.archive_mdp_rows (brand, partner);

create index if not exists archive_mdp_brand_idx
on public.archive_mdp_rows (brand);

create table if not exists public.archive_ax_rows (
  id bigserial primary key,
  brand text not null,
  invoice_date date,
  net_sales numeric not null default 0,
  uploaded_at timestamptz not null default now()
);

create index if not exists archive_ax_brand_idx
on public.archive_ax_rows (brand);

alter table public.archive_mdp_rows enable row level security;
alter table public.archive_ax_rows enable row level security;

-- Remove old archive policies if this script is rerun.
do $$
declare r record;
begin
  for r in select policyname from pg_policies
           where schemaname='public' and tablename='archive_mdp_rows'
  loop
    execute format('drop policy if exists %I on public.archive_mdp_rows', r.policyname);
  end loop;

  for r in select policyname from pg_policies
           where schemaname='public' and tablename='archive_ax_rows'
  loop
    execute format('drop policy if exists %I on public.archive_ax_rows', r.policyname);
  end loop;
end $$;

-- MDP Archive: admin sees all.
-- Normal user: same Brand AND Partner permissions as the main system.
create policy "archive_mdp_select_permitted_or_admin"
on public.archive_mdp_rows
for select to authenticated
using (
  public.is_admin()
  or (
    exists (
      select 1 from public.permissions b
      where b.user_id = auth.uid()
        and b.perm_type = 'brand'
        and lower(trim(b.value)) = lower(trim(archive_mdp_rows.brand))
    )
    and exists (
      select 1 from public.permissions p
      where p.user_id = auth.uid()
        and p.perm_type = 'partner'
        and lower(trim(p.value)) = lower(trim(archive_mdp_rows.partner))
    )
  )
);

create policy "archive_mdp_admin_write"
on public.archive_mdp_rows
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

-- AX / Miami Center:
-- It is part of the selected Brand archive, so authenticated users may read
-- rows only for Brands they are allowed to access. Admin sees all.
create policy "archive_ax_select_brand_or_admin"
on public.archive_ax_rows
for select to authenticated
using (
  public.is_admin()
  or exists (
    select 1 from public.permissions b
    where b.user_id = auth.uid()
      and b.perm_type = 'brand'
      and lower(trim(b.value)) = lower(trim(archive_ax_rows.brand))
  )
);

create policy "archive_ax_admin_write"
on public.archive_ax_rows
for all to authenticated
using (public.is_admin())
with check (public.is_admin());

grant select, insert, update, delete
on public.archive_mdp_rows, public.archive_ax_rows
to authenticated;

grant usage, select on all sequences in schema public to authenticated;