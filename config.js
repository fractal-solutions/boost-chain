import { randomBytes, createHash } from 'crypto';

// Generate a secure random key and hash it to get exactly 32 bytes
const generateEncryptionKey = () => {
    return createHash('sha256')
        .update(randomBytes(32))
        .digest('hex')
        .slice(0, 32); // Take first 32 bytes
};

export const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';
export const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || generateEncryptionKey();

export const corsHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };



export const PRODUCTION = true;
export const chain_ip = PRODUCTION ?  'http://192.9.241.89:8222' : 'http://127.0.0.1:2222';
export const metadata_ip = PRODUCTION ?  'http://192.9.241.89:8224': 'http://localhost:2224';
export const users_ip = PRODUCTION ?  'http://192.9.241.89:8225': 'http://localhost:2225';
export const smartcron_ip = PRODUCTION ? 'http://192.9.241.89:8223': 'http://127.0.0.1:2223';