import { ROLES, hasPermission } from './roles.js';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './config.js';

export function authenticateToken(req) {
    try {
        const authHeader = req.headers.get('Authorization');
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
        
        if (!token) {
            return {
                authenticated: false,
                error: 'No token provided',
                status: 401
            };
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded) {
            return {
                authenticated: false,
                error: 'Invalid token',
                status: 403
            };
        }

        return {
            authenticated: true,
            user: decoded
        };
    } catch (error) {
        return {
            authenticated: false,
            error: error.message,
            status: 403
        };
    }
}

export function requirePermission(permission) {
    return (req) => {
        const auth = authenticateToken(req);
        if (!auth.authenticated) {
            return auth;
        }

        if (!hasPermission(auth.user.role, permission)) {
            return {
                authenticated: false,
                error: `Permission denied: ${permission} required`,
                status: 403
            };
        }

        return auth;
    };
}

export function requireRole(allowedRoles) {
    return (req) => {
        const auth = authenticateToken(req);
        if (!auth.authenticated) {
            return auth;
        }

        if (!allowedRoles.includes(auth.user.role)) {
            return {
                authenticated: false,
                error: `Role denied: ${allowedRoles.join(' or ')} required`,
                status: 403
            };
        }

        return auth;
    };
}