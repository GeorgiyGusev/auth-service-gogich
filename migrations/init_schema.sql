-- Создание схемы если не существует
CREATE SCHEMA IF NOT EXISTS identities;

-- Создание таблицы
CREATE TABLE IF NOT EXISTS identities.identities (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    identity TEXT NOT NULL UNIQUE ,
    identity_type TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    hash_type TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT current_timestamp,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp
);

CREATE INDEX identities_created_at ON identities.identities(created_at);


-- Создание функции для обновления updated_at
CREATE OR REPLACE FUNCTION identities.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Создание триггера
DROP TRIGGER IF EXISTS update_identities_updated_at ON identities.identities;
CREATE TRIGGER update_identities_updated_at
    BEFORE UPDATE ON identities.identities
    FOR EACH ROW
    EXECUTE FUNCTION identities.update_updated_at_column();


-- DROP SCHEMA identities CASCADE