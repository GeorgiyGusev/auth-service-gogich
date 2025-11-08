-- Создание схемы если не существует
CREATE SCHEMA IF NOT EXISTS identities;

-- Создание таблицы
CREATE TABLE IF NOT EXISTS identities.users (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT current_timestamp,
    updated_at TIMESTAMPTZ DEFAULT current_timestamp
);

CREATE INDEX users_created_at ON identities.users(created_at);


-- Создание функции для обновления updated_at
CREATE OR REPLACE FUNCTION identities.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Создание триггера
DROP TRIGGER IF EXISTS update_users_updated_at ON identities.users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON identities.users
    FOR EACH ROW
    EXECUTE FUNCTION identities.update_updated_at_column();


-- DROP SCHEMA identities CASCADE