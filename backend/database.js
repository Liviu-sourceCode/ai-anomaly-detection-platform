// Load environment variables
import 'dotenv/config';
import mysql from 'mysql2/promise';
import { database } from './config.js';

export const db = await mysql.createConnection({
    host: process.env.DB_HOST || database.host,
    user: process.env.DB_USER || database.user,
    password: process.env.DB_PASSWORD || database.password,
    database: process.env.DB_NAME || database.database
});

// Create users table if it doesn't exist
await db.query(`
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        twofa_secret VARCHAR(255) DEFAULT NULL,
        twofa_enabled BOOLEAN DEFAULT FALSE,
        backup_codes TEXT DEFAULT NULL
    )
`);

await db.query(`
    CREATE TABLE IF NOT EXISTS suricata_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        timestamp DATETIME NOT NULL,
        signature VARCHAR(255),
        category VARCHAR(255),
        severity INT,
        src_ip VARCHAR(45),
        dest_ip VARCHAR(45)
    )
`);