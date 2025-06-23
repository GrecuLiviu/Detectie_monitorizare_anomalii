import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env file from the correct path
dotenv.config({ path: resolve(__dirname, '../.env') });

// Validate required environment variables
const requiredEnvVars = [
    'SSH_HOST',
    'SSH_USER',
    'SSH_PASSWORD',
    'DB_HOST',
    'DB_USER',
    'DB_PASSWORD',
    'DB_NAME',
    'SESSION_SECRET'
];

for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        throw new Error(`Missing required environment variable: ${envVar}`);
    }
}

export const ssh = {
    host: process.env.SSH_HOST,
    port: parseInt(process.env.SSH_PORT) || 22,
    username: process.env.SSH_USER,
    password: process.env.SSH_PASSWORD
};

export const suricata = {
    logPath: process.env.SURICATA_LOG_PATH
};

export const apache = {
    statusCommand: process.env.APACHE_STATUS_COMMAND || 'systemctl status apache2'
};

export const server = {
    port: parseInt(process.env.PORT) || 3000,
    staticDir: process.env.STATIC_DIR || '../public',
    shutdownTimeout: parseInt(process.env.SHUTDOWN_TIMEOUT) || 5000
};

export const database = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
};

export const session = {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: parseInt(process.env.SESSION_MAX_AGE) || 24 * 60 * 60 * 1000,
        sameSite: 'strict'
    }
};