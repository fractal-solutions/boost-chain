import { SmartContract } from "./smartContract.js";
import { Transaction } from "./transaction.js";
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './config.js';

// Investment Pool status constants
const POOL_STATUS = {
    OPEN: 'OPEN',
    THRESHOLD_MET: 'THRESHOLD_MET',
    ACTIVE: 'ACTIVE',
    COMPLETED: 'COMPLETED',
    CLOSED: 'CLOSED'
};

class InvestmentPool {
    constructor(options) {
        this.id = crypto.randomUUID();
        this.name = options.name;
        this.description = options.description;
        this.totalSupply = options.totalSupply;
        this.threshold = options.threshold;
        this.currentAmount = 0;
        this.interestRate = options.interestRate;
        this.duration = options.duration; // in milliseconds
        this.borrowers = new Map(); // Map of borrower public keys to amounts
        this.lenders = new Map(); // Map of lender public keys to amounts
        this.status = POOL_STATUS.OPEN;
        this.contracts = new Map(); // Map of contractIds to SmartContract instances
        this.createdAt = Date.now();

        // Generate pool's keypair
        const keyPair = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        
        this.publicKey = keyPair.publicKey;
        this.privateKey = keyPair.privateKey;
        this.balance = 0;
    }

    addLender(publicKey, amount) {
        if (this.status !== POOL_STATUS.OPEN) {
            throw new Error('Pool is not open for investment');
        }
        if (this.currentAmount + amount > this.totalSupply) {
            throw new Error('Investment would exceed pool supply');
        }
        this.lenders.set(publicKey, (this.lenders.get(publicKey) || 0) + amount);
        this.currentAmount += amount;
        
        if (this.currentAmount >= this.threshold) {
            this.status = POOL_STATUS.THRESHOLD_MET;
        }
    }

    addBorrower(publicKey, amount, privateKey, token) {
        if (this.status !== POOL_STATUS.OPEN) {
            throw new Error('Pool is not open for borrowers');
        }
        const totalBorrowed = Array.from(this.borrowers.values()).reduce((a, b) => a + b, 0);
        if (totalBorrowed + amount > this.totalSupply) {
            throw new Error('Borrow amount would exceed pool supply');
        }
        this.borrowers.set(publicKey, {
            amount,
            privateKey,
            token, // Store the auth token
            signedOff: false
        });
    }

    signOffBorrower(publicKey) {
        const borrower = this.borrowers.get(publicKey);
        if (!borrower) {
            throw new Error('Borrower not found');
        }
        borrower.signedOff = true;

        // Check if all borrowers have signed off
        const allSignedOff = Array.from(this.borrowers.values())
            .every(b => b.signedOff);
            
        if (allSignedOff && this.status === POOL_STATUS.THRESHOLD_MET) {
            this.status = POOL_STATUS.ACTIVE;
        }
    }

    async createRepaymentContracts() {
        if (this.status !== POOL_STATUS.ACTIVE) {
            throw new Error('Pool not ready for contract creation');
        }

        const contracts = [];

        // 1. Create contracts for borrowers to pay the pool
        for (const [borrowerKey, borrowerData] of this.borrowers) {
            try {
                // Calculate total monthly payment including interest
                const monthlyInterest = (borrowerData.amount * this.interestRate) / 12;

                // Create borrower->pool contract
                const borrowerContract = await fetch('http://localhost:2223/contract', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${borrowerData.token}`,
                    },
                    body: JSON.stringify({
                        creator: {
                            publicKey: borrowerKey,
                            privateKey: borrowerData.privateKey
                        },
                        participants: [{ publicKey: this.publicKey }],
                        amount: monthlyInterest,
                        interval: 30 * 24 * 60 * 60 * 1000, // 30 days
                        startDate: Date.now(),
                        endDate: Date.now() + this.duration,
                        type: 'POOL_PAYMENT'
                    })
                });

                if (!borrowerContract.ok) {
                    throw new Error('Failed to create borrower contract');
                }
                
                contracts.push(await borrowerContract.json());
            } catch (error) {
                console.error('Borrower contract creation failed:', error);
                throw error;
            }
        }

        // 2. Create contracts for pool to pay lenders
        for (const [lenderKey, lentAmount] of this.lenders) {
            try {
                // Calculate proportional payment for this lender
                const proportion = lentAmount / this.currentAmount;
                const monthlyInterestShare = this.getTotalMonthlyInterest() * proportion;

                // Create pool->lender contract
                const lenderContract = await fetch('http://localhost:2223/contract', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${await this.generatePoolToken()}`,
                    },
                    body: JSON.stringify({
                        creator: {
                            publicKey: this.publicKey,
                            privateKey: this.privateKey
                        },
                        participants: [{ publicKey: lenderKey }],
                        amount: monthlyInterestShare,
                        interval: 30 * 24 * 60 * 60 * 1000, // 30 days
                        startDate: Date.now() + (60 * 60 * 1000), // 1 hour delay after borrower payments
                        endDate: Date.now() + this.duration,
                        type: 'POOL_DISTRIBUTION'
                    })
                });

                if (!lenderContract.ok) {
                    throw new Error('Failed to create lender contract');
                }

                contracts.push(await lenderContract.json());
            } catch (error) {
                console.error('Lender contract creation failed:', error);
                throw error;
            }
        }

        // Store all contracts
        contracts.forEach(contract => {
            this.contracts.set(contract.contractId, contract);
        });

        return contracts;
    }

    // Helper method to calculate total monthly interest
    getTotalMonthlyInterest() {
        return Array.from(this.borrowers.values())
            .reduce((total, borrower) => {
                return total + (borrower.amount * this.interestRate) / 12;
            }, 0);
    }

    // Generate JWT token for pool operations
    async generatePoolToken() {
        return jwt.sign(
            {
                poolId: this.id,
                publicKey: this.publicKey,
                type: 'POOL',
                permissions: ['execute_contract_payment']
            },
            JWT_SECRET,
            { expiresIn: '1y' }
        );
    }
}

class InvestmentManager {
    constructor() {
        this.pools = new Map();
    }

    createPool(options) {
        const pool = new InvestmentPool(options);
        this.pools.set(pool.id, pool);
        return pool;
    }

    getPool(id) {
        return this.pools.get(id);
    }

    getAllPools() {
        return Array.from(this.pools.values());
    }

    getActivePools() {
        return Array.from(this.pools.values())
            .filter(pool => pool.status === POOL_STATUS.OPEN);
    }
}

// Initialize investment manager
const investmentManager = new InvestmentManager();

// CORS headers
const corsHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// Start investment server
console.log('Starting INVESTMENT Server on port 2227...');
Bun.serve({
    port: 2227,
    routes: {
        // Create new investment pool
        '/pool': {
            POST: async (req) => {
                try {
                    const data = await req.json();
                    const pool = investmentManager.createPool({
                        name: data.name,
                        description: data.description,
                        totalSupply: Number(data.totalSupply),
                        threshold: Number(data.threshold),
                        interestRate: Number(data.interestRate),
                        duration: Number(data.duration)
                    });

                    return Response.json({
                        success: true,
                        poolId: pool.id
                    }, { headers: corsHeaders });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        // Get pool details
        '/pool/:id': {
            GET: async (req) => {
                const id = req.params.id;
                const pool = investmentManager.getPool(id);
                if (!pool) {
                    return Response.json({
                        success: false,
                        error: 'Pool not found'
                    }, { 
                        status: 404,
                        headers: corsHeaders 
                    });
                }
                return Response.json({
                    success: true,
                    pool: {
                        ...pool,
                        borrowers: Array.from(pool.borrowers.entries()),
                        lenders: Array.from(pool.lenders.entries())
                    }
                }, { headers: corsHeaders });
            }
        },

        // Invest in pool
        '/pool/:id/invest': {
            POST: async (req) => {
                try {
                    const id = req.params.id;
                    const pool = investmentManager.getPool(id);
                    if (!pool) {
                        throw new Error('Pool not found');
                    }

                    const data = await req.json();
                    pool.addLender(data.publicKey, Number(data.amount));

                    return Response.json({
                        success: true,
                        currentAmount: pool.currentAmount,
                        status: pool.status
                    }, { headers: corsHeaders });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        // Add borrower to pool
        '/pool/:id/borrow': {
            POST: async (req) => {
                try {
                    const id = req.params.id;
                    const pool = investmentManager.getPool(id);
                    if (!pool) {
                        throw new Error('Pool not found');
                    }

                    const data = await req.json();
                    const token = req.headers.get('authorization');
                    if (!token) {
                        throw new Error('Authorization token required');
                    }

                    pool.addBorrower(
                        data.publicKey,
                        Number(data.amount),
                        data.privateKey,
                        token
                    );

                    return Response.json({
                        success: true,
                        currentBorrowers: Array.from(pool.borrowers.keys())
                    }, { headers: corsHeaders });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        // Borrower sign-off
        '/pool/:id/signoff': {
            POST: async (req) => {
                try {
                    const id = req.params.id;
                    const pool = investmentManager.getPool(id);
                    if (!pool) {
                        throw new Error('Pool not found');
                    }

                    const data = await req.json();
                    pool.signOffBorrower(data.publicKey);

                    if (pool.status === POOL_STATUS.ACTIVE) {
                        await pool.createRepaymentContracts();
                    }

                    return Response.json({
                        success: true,
                        status: pool.status
                    }, { headers: corsHeaders });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        // Get all active pools
        '/pools/active': {
            GET: async () => {
                const pools = investmentManager.getActivePools();
                return Response.json({
                    success: true,
                    pools: pools.map(pool => ({
                        id: pool.id,
                        name: pool.name,
                        description: pool.description,
                        totalSupply: pool.totalSupply,
                        currentAmount: pool.currentAmount,
                        threshold: pool.threshold,
                        status: pool.status
                    }))
                }, { headers: corsHeaders });
            }
        },

        // Handle CORS preflight
        '/*': {
            OPTIONS: () => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            }
        }
    }
});