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

        const user = userManager.validateToken(token);
        if (!user) {
            return {
                authenticated: false,
                error: 'Invalid token',
                status: 403
            };
        }

        return {
            authenticated: true,
            user
        };
    } catch (error) {
        return {
            authenticated: false,
            error: error.message,
            status: 403
        };
    }
}

export function requireRole(roles) {
    return (req) => {
        const auth = authenticateToken(req);
        if (!auth.authenticated) {
            return auth;
        }

        if (!roles.includes(auth.user.role)) {
            return {
                authenticated: false,
                error: 'Insufficient permissions',
                status: 403
            };
        }

        return auth;
    };
}