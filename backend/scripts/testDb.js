// Load environment variables first
import 'dotenv/config';
import { db } from '../database.js';

async function testConnection() {
    try {
        // Test the connection
        const [result] = await db.query('SELECT 1');
        console.log('✅ Database connection successful!');
        
        // Check if users table was created
        const [tables] = await db.query('SHOW TABLES');
        console.log('\nExisting tables:', tables.map(t => Object.values(t)[0]).join(', '));
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
    } finally {
        await db.end();
    }
}

testConnection();