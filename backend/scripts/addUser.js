// Load environment variables first
import 'dotenv/config';
import { db } from '../database.js';
import bcrypt from 'bcrypt';

async function addUser(username, password) {
    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert the user into the database
        await db.query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );
        
        console.log(`✅ User '${username}' created successfully!`);
    } catch (error) {
        console.error('❌ Failed to create user:', error.message);
    } finally {
        // Close the database connection
        await db.end();
    }
}

// Check if username and password were provided as command line arguments
const username = process.argv[2];
const password = process.argv[3];

if (!username || !password) {
    console.error('❌ Usage: node addUser.js <username> <password>');
    process.exit(1);
}

// Add the user
addUser(username, password);