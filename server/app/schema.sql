-- Lot 1 — schéma Postgres (SPEC §5), repris tel quel.
-- gen_random_uuid() est natif depuis PostgreSQL 13, aucune extension requise.

CREATE TABLE IF NOT EXISTS member (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matricule    text UNIQUE NOT NULL,        -- identité stable, survit au renouvellement de clé
  display_name text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS member_key (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  member_id     uuid NOT NULL REFERENCES member(id),
  age_recipient text  NOT NULL,             -- "age1..."
  ed25519_pub   bytea NOT NULL,
  wrapped_seed  bytea NOT NULL,             -- keyblob, age mode passphrase
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS member_key_one_active
  ON member_key (member_id) WHERE active;

CREATE TABLE IF NOT EXISTS grp (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS epoch (
  group_id     uuid NOT NULL REFERENCES grp(id),
  n            int  NOT NULL,
  gk_envelope  bytea NOT NULL,              -- age, GK chiffrée vers tous les membres
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, n)
);

CREATE TABLE IF NOT EXISTS grant_stmt (
  group_id      uuid  NOT NULL REFERENCES grp(id),
  seq           int   NOT NULL,
  stmt          bytea NOT NULL,             -- CBOR, octets exacts signés
  sig           bytea NOT NULL,
  signer_key_id uuid  NOT NULL REFERENCES member_key(id),
  hash          bytea NOT NULL,             -- blake2b-256(stmt)
  PRIMARY KEY (group_id, seq)
);

CREATE TABLE IF NOT EXISTS note (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id    uuid NOT NULL REFERENCES grp(id),
  epoch_n     int  NOT NULL,
  author_id   uuid NOT NULL REFERENCES member(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  wrapped_cek bytea NOT NULL,
  payload     bytea NOT NULL,               -- AEAD, seul champ opaque
  FOREIGN KEY (group_id, epoch_n) REFERENCES epoch(group_id, n)
);
CREATE INDEX IF NOT EXISTS note_group_created ON note (group_id, created_at DESC);
