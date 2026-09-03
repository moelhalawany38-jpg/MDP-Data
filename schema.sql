-- ============================================================
-- MDP Data — Database Schema for Supabase (v3 — دعم صلاحية "الكل")
-- شغّل الكود ده كامل في Supabase Dashboard -> SQL Editor -> Run
-- لو كنت شغّلت نسخة قديمة قبل كده وعندك داتا فعلًا، الكود ده آمن
-- (create table if not exists + drop/create policy) ومش هيمسح حاجة،
-- بس لازم تشغّله تاني عشان يحدّث الـ RLS policy بتاعة data_rows
-- عشان تفهم صلاحية "كل البراندات / كل البارتنرز" (قيمة '*').
-- ============================================================

-- 1) بروفايل لكل مستخدم (بيتربط تلقائي بحساب تسجيل الدخول)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  is_admin boolean not null default false,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
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

-- 2) القوائم الرئيسية (اللي الأدمن بيضيف عليها من لوحته)
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

-- 3) صلاحيات المستخدمين: كل صف = يوزر مسموحله يشوف برand معين أو partner معين
create table if not exists public.permissions (
  id bigserial primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  perm_type text not null check (perm_type in ('brand','partner')),
  value text not null,
  created_at timestamptz not null default now(),
  unique (user_id, perm_type, value)
);

-- 4) الداتا نفسها (بيتمسح ويتستبدل كل يوم بالكامل)
-- brand = العمود الرابع في الشيت | partner = العمود التاني في الشيت
-- row_data فيها كل الـ 31 عمود زي ما هما بالظبط
create table if not exists public.data_rows (
  id bigserial primary key,
  brand text not null,
  partner text not null,
  row_data jsonb not null,
  uploaded_at timestamptz not null default now()
);
create index if not exists data_rows_brand_idx on public.data_rows (brand);
create index if not exists data_rows_partner_idx on public.data_rows (partner);

-- 5) ترتيب الأعمدة الأصلي بتاع آخر رفعة (عشان الداونلود يطلع بنفس شكل الشيت)
create table if not exists public.data_columns (
  id int primary key default 1,
  columns jsonb not null,
  brand_col_index int not null default 4,
  partner_col_index int not null default 2,
  updated_at timestamptz not null default now(),
  constraint single_row check (id = 1)
);

-- ============================================================
-- Helper: هل اليوزر الحالي أدمن؟
-- ============================================================
create or replace function public.is_admin()
returns boolean
language sql
security definer set search_path = public
stable
as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

-- ============================================================
-- تفعيل الحماية على كل الجداول
-- ============================================================
alter table public.profiles enable row level security;
alter table public.brands enable row level security;
alter table public.partners enable row level security;
alter table public.permissions enable row level security;
alter table public.data_rows enable row level security;
alter table public.data_columns enable row level security;

-- ---- profiles ----
drop policy if exists "profiles_select_own_or_admin" on public.profiles;
create policy "profiles_select_own_or_admin" on public.profiles
  for select using (id = auth.uid() or public.is_admin());
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles
  for update using (public.is_admin());

-- ---- brands / partners (كل مستخدم مسجل دخول يقدر يشوف القايمة، الأدمن بس يعدل) ----
drop policy if exists "brands_select_auth" on public.brands;
create policy "brands_select_auth" on public.brands for select using (auth.uid() is not null);
drop policy if exists "brands_write_admin" on public.brands;
create policy "brands_write_admin" on public.brands for insert with check (public.is_admin());
drop policy if exists "brands_delete_admin" on public.brands;
create policy "brands_delete_admin" on public.brands for delete using (public.is_admin());

drop policy if exists "partners_select_auth" on public.partners;
create policy "partners_select_auth" on public.partners for select using (auth.uid() is not null);
drop policy if exists "partners_write_admin" on public.partners;
create policy "partners_write_admin" on public.partners for insert with check (public.is_admin());
drop policy if exists "partners_delete_admin" on public.partners;
create policy "partners_delete_admin" on public.partners for delete using (public.is_admin());

-- ---- permissions ----
drop policy if exists "perm_select_own_or_admin" on public.permissions;
create policy "perm_select_own_or_admin" on public.permissions
  for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists "perm_write_admin" on public.permissions;
create policy "perm_write_admin" on public.permissions for insert with check (public.is_admin());
drop policy if exists "perm_delete_admin" on public.permissions;
create policy "perm_delete_admin" on public.permissions for delete using (public.is_admin());

-- ---- data_rows ----
-- المستخدم بيشوف الصف لو: أدمن، أو عنده صلاحية برand مطابقة، أو عنده صلاحية partner مطابقة
-- value = '*' معناها "كل البراندات" أو "كل البارتنرز" حسب النوع
drop policy if exists "data_select_permitted_or_admin" on public.data_rows;
create policy "data_select_permitted_or_admin" on public.data_rows
  for select using (
    public.is_admin()
    or exists (
      select 1 from public.permissions p
      where p.user_id = auth.uid()
        and (
          (p.perm_type = 'brand' and (p.value = data_rows.brand or p.value = '*'))
          or (p.perm_type = 'partner' and (p.value = data_rows.partner or p.value = '*'))
        )
    )
  );
drop policy if exists "data_write_admin" on public.data_rows;
create policy "data_write_admin" on public.data_rows for insert with check (public.is_admin());
drop policy if exists "data_delete_admin" on public.data_rows;
create policy "data_delete_admin" on public.data_rows for delete using (public.is_admin());

-- ---- data_columns ----
drop policy if exists "cols_select_authenticated" on public.data_columns;
create policy "cols_select_authenticated" on public.data_columns for select using (auth.uid() is not null);
drop policy if exists "cols_write_admin" on public.data_columns;
create policy "cols_write_admin" on public.data_columns for insert with check (public.is_admin());
drop policy if exists "cols_update_admin" on public.data_columns;
create policy "cols_update_admin" on public.data_columns for update using (public.is_admin());

-- ============================================================
-- أول ما تشغل الكود ده: سجّل حساب من صفحة تسجيل الدخول بإيميل/باسورد
-- بتاعتك، وبعدين شغّل السطر ده لتحويله لأدمن (بدّل الإيميل):
-- ============================================================
-- update public.profiles set is_admin = true where email = 'you@mdp.local';
