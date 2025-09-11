-- QUOTES (main)
CREATE TABLE IF NOT EXISTS quotes (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL,
  treatment   TEXT,
  email       TEXT NOT NULL,
  phone       TEXT NOT NULL,
  whatsapp    TEXT,
  country     TEXT,
  notes       TEXT,
  consent     BOOLEAN DEFAULT FALSE,
  status      TEXT NOT NULL DEFAULT 'pending'
              CHECK (status IN ('pending','reviewing','quoted','scheduled','closed','cancelled')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- FILES (attachments)
CREATE TABLE IF NOT EXISTS files (
  id            SERIAL PRIMARY KEY,
  quote_id      INTEGER NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
  original_name TEXT,
  mime_type     TEXT,
  size          BIGINT,
  path          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
