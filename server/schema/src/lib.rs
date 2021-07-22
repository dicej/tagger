#![deny(warnings)]

pub static DDL_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS paths (
       path          TEXT NOT NULL PRIMARY KEY,
       hash          TEXT NOT NULL
     )",
    "CREATE TABLE IF NOT EXISTS images (
       hash          TEXT NOT NULL PRIMARY KEY,
       datetime      TEXT NOT NULL,
       video_offset  INTEGER
     )",
    "CREATE TABLE IF NOT EXISTS tags (
       hash          TEXT NOT NULL,
       tag           TEXT NOT NULL,
       category      TEXT,

       PRIMARY KEY (hash, tag, category),
       FOREIGN KEY (hash) REFERENCES images(hash) ON DELETE CASCADE,
       FOREIGN KEY (category) REFERENCES categories(name) ON DELETE CASCADE
     )",
    "CREATE TABLE IF NOT EXISTS categories (
       name          TEXT NOT NULL,
       parent        TEXT,
       immutable     INTEGER NOT NULL DEFAULT 0,

       PRIMARY KEY (name),
       FOREIGN KEY (parent) REFERENCES categories(name) ON DELETE CASCADE
     )",
    "INSERT INTO categories (name, parent, immutable)
     VALUES ('year', NULL, 1), ('month', 'year', 1) ON CONFLICT DO NOTHING",
    "CREATE TABLE IF NOT EXISTS users (
       name          TEXT NOT NULL,
       password_hash TEXT NOT NULL,

       PRIMARY KEY (name, password_hash)
     )",
];
