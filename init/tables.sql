CREATE TABLE IF NOT EXISTS kyc_files (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128),
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);