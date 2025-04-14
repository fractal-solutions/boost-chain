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