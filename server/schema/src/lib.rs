#![deny(warnings)]

pub static DDL_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS paths (
       path      TEXT NOT NULL PRIMARY KEY,
       hash      TEXT NOT NULL
     )",
    "CREATE TABLE IF NOT EXISTS images (
       hash      TEXT NOT NULL PRIMARY KEY,
       datetime  TEXT NOT NULL,
       small     BLOB,
       large     BLOB
     )",
    "CREATE TABLE IF NOT EXISTS tags (
       hash      TEXT NOT NULL,
       tag       TEXT NOT NULL,

       PRIMARY KEY (hash, tag),
       FOREIGN KEY (hash) REFERENCES images(hash) ON DELETE CASCADE
     )",
];
