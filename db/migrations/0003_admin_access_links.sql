-- Access links for the admin UI (plan §11.1): a link opens one site, or the admin UI on the
-- admin host name. site_id stays the foreign key of site links (deleted with their site).
ALTER TABLE access_links ALTER COLUMN site_id DROP NOT NULL;
ALTER TABLE access_links ADD COLUMN target text NOT NULL DEFAULT 'site' CHECK (target IN ('site', 'admin'));
ALTER TABLE access_links ADD CONSTRAINT access_links_target_site CHECK ((target = 'site') = (site_id IS NOT NULL));

-- Cleared addresses: "scope" is the key nginx checks ($pspm_site): the site id, or 'admin'.
ALTER TABLE cleared_ips DROP CONSTRAINT cleared_ips_pkey;
ALTER TABLE cleared_ips ALTER COLUMN site_id DROP NOT NULL;
ALTER TABLE cleared_ips ADD COLUMN scope text GENERATED ALWAYS AS (coalesce(site_id::text, 'admin')) STORED;
ALTER TABLE cleared_ips ADD PRIMARY KEY (scope, ip);
