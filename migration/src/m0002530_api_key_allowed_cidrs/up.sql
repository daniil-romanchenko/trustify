-- Optional network ranges an API key may be used from.
ALTER TABLE api_key
    ADD COLUMN IF NOT EXISTS allowed_cidrs TEXT[] NULL;
