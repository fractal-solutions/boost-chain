export const ROLES = {
    ADMIN: 'ADMIN',
    VENDOR: 'VENDOR',
    USER: 'USER',
    SME: 'SME',
    VALIDATOR: 'VALIDATOR',
    SERVICE: 'SERVICE' // Add SERVICE role
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
    VENDOR: [
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
    ],
    SERVICE: [
        'transfer',
        'contract_payment'
    ]
};

export function hasPermission(userRole, requiredPermission) {
    return PERMISSIONS[userRole]?.includes(requiredPermission) || false;
}