export const ROLES = {
    ADMIN: 'ADMIN',
    SME: 'SME',
    USER: 'USER',
    VALIDATOR: 'VALIDATOR'
};

export const PERMISSIONS = {
    ADMIN: [
        'manage_users',
        'view_all_transactions',
        'manage_nodes',
        'deposit',
        'withdraw',
        'transfer',
        'view_chain'
    ],
    SME: [
        'transfer',
        'deposit',
        'withdraw',
        'view_own_transactions',
        'view_chain'
    ],
    USER: [
        'transfer',
        'deposit',
        'withdraw',
        'view_own_transactions'
    ],
    VALIDATOR: [
        'validate_transactions',
        'view_chain',
        'view_all_transactions'
    ]
};

export function hasPermission(userRole, requiredPermission) {
    return PERMISSIONS[userRole]?.includes(requiredPermission) || false;
}