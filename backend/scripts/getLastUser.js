import 'dotenv/config';
import { db } from '../database.js';

async function printLastUser() {
    try {
        const [rows] = await db.query(
            'SELECT id, username, created_at, twofa_enabled FROM users ORDER BY created_at DESC LIMIT 1'
        );

        if (!rows || rows.length === 0) {
            console.log('No users found in the database.');
            return;
        }

        const user = rows[0];
        console.log('Last user created:');
        console.log(`id: ${user.id}`);
        console.log(`username: ${user.username}`);
        console.log(`created_at: ${user.created_at}`);
        console.log(`twofa_enabled: ${user.twofa_enabled}`);
    } catch (err) {
        console.error('Error querying database:', err.message);
    } finally {
        try { await db.end(); } catch (e) { /* ignore */ }
    }
}

printLastUser();
