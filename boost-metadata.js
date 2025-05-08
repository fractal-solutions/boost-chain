import { createHash } from "crypto";
process.env.NETWORK_SECRET = 'test-secret-123';

class ChainAnalytics {
    constructor() {
        this.chain = [];
        this.lastSync = null;
        this.syncInterval = 60000; // 1 minute
        this.startSync();
    }

    async startSync() {
        // Initial sync
        await this.syncChain();
        
        // Regular sync interval
        setInterval(async () => {
            await this.syncChain();
        }, this.syncInterval);
    }

    async syncChain() {
        try {
            const response = await fetch('http://localhost:2222/chain', {
                headers: { 'x-auth-token': process.env.NETWORK_SECRET }
            });
            
            if (!response.ok) {
                console.log(new Error('Failed to fetch chain'));
            }
    
            const { chain } = await response.json();
            this.chain = chain;
            this.lastSync = Date.now();
            
            // Debug log for contract payments
            console.log('Chain sync complete. Found transactions:');
            for (const block of this.chain) {
                for (const tx of block.transactions) {
                    if (Array.isArray(tx) || tx.type === "CONTRACT_PAYMENT") {
                        console.log('Contract Payment:', {
                            type: Array.isArray(tx) ? 'Array' : tx.type,
                            sender: Array.isArray(tx) ? tx[0].sender : tx.sender,
                            recipient: Array.isArray(tx) ? tx[0].recipient : tx.recipient,
                            amount: Array.isArray(tx) ? tx[0].amount : tx.amount
                        });
                    }
                }
            }
            
            console.log(`Chain synced at ${new Date(this.lastSync).toISOString()}`);
        } catch (error) {
            console.error('Chain sync failed:', error);
        }
    }

    static normalizeAddress(address) {
        if (!address) return '';
        
        // Extract base64 part between the PEM headers
        if (address.includes('-----BEGIN PUBLIC KEY-----')) {
            return address
                .replace('-----BEGIN PUBLIC KEY-----', '')
                .replace('-----END PUBLIC KEY-----', '')
                .replace(/\n/g, '')
                .trim();
        }
        
        // If already normalized, return as is
        return address.trim();
    }

    getBalance(address) {
        const normalizedAddress = ChainAnalytics.normalizeAddress(address);
        let balance = 0;
    
        // Process regular transactions and contract payments
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                // Handle array of transactions (contract payment bundle)
                if (Array.isArray(tx)) {
                    for (const subTx of tx) {
                        if (subTx.type === "CONTRACT_PAYMENT" || subTx.type === "FEE") {
                            if (ChainAnalytics.normalizeAddress(subTx.sender) === normalizedAddress) {
                                balance -= Number(subTx.amount);
                            }
                            if (ChainAnalytics.normalizeAddress(subTx.recipient) === normalizedAddress) {
                                balance += Number(subTx.amount);
                            }
                        }
                    }
                } 
                // Handle single transaction
                else {
                    if (ChainAnalytics.normalizeAddress(tx.sender) === normalizedAddress) {
                        balance -= Number(tx.amount);
                    }
                    if (ChainAnalytics.normalizeAddress(tx.recipient) === normalizedAddress) {
                        balance += Number(tx.amount);
                    }
                }
            }
        }
        return balance;
    }

    getTransactionHistory(address) {
        const normalizedAddress = ChainAnalytics.normalizeAddress(address);
        const history = [];
    
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                // Handle array of transactions (contract payment bundle)
                if (Array.isArray(tx)) {
                    for (const subTx of tx) {
                        if (subTx.type === "CONTRACT_PAYMENT" || subTx.type === "FEE") {
                            if (ChainAnalytics.normalizeAddress(subTx.sender) === normalizedAddress || 
                                ChainAnalytics.normalizeAddress(subTx.recipient) === normalizedAddress) {
                                history.push({
                                    type: ChainAnalytics.normalizeAddress(subTx.sender) === normalizedAddress ? 'SENT' : 'RECEIVED',
                                    transactionType: subTx.type,
                                    amount: Number(subTx.amount),
                                    counterparty: ChainAnalytics.normalizeAddress(subTx.sender) === normalizedAddress ? 
                                        subTx.recipient : subTx.sender,
                                    timestamp: subTx.timestamp,
                                    blockHeight: block.index,
                                    contractPayment: true
                                });
                            }
                        }
                    }
                } 
                // Handle single transaction
                else {
                    if (ChainAnalytics.normalizeAddress(tx.sender) === normalizedAddress || 
                        ChainAnalytics.normalizeAddress(tx.recipient) === normalizedAddress) {
                        history.push({
                            type: ChainAnalytics.normalizeAddress(tx.sender) === normalizedAddress ? 'SENT' : 'RECEIVED',
                            transactionType: tx.type || 'TRANSFER',
                            amount: Number(tx.amount),
                            counterparty: ChainAnalytics.normalizeAddress(tx.sender) === normalizedAddress ? 
                                tx.recipient : tx.sender,
                            timestamp: tx.timestamp,
                            blockHeight: block.index,
                            contractPayment: tx.type === "CONTRACT_PAYMENT"
                        });
                    }
                }
            }
        }
        return history.sort((a, b) => b.timestamp - a.timestamp);
    }

    getLastTransactions(address, limit = 10) {
        if (address === 'all') {
            // Get all transactions from all addresses
            const allTransactions = [];
            for (const block of this.chain) {
                for (const tx of block.transactions) {
                    if (Array.isArray(tx)) {
                        allTransactions.push(...tx);
                    } else {
                        allTransactions.push(tx);
                    }
                }
            }
            return allTransactions
                .sort((a, b) => b.timestamp - a.timestamp)
                .slice(0, limit);
        }
        return this.getTransactionHistory(address).slice(0, limit);
    }

    getContractPayments(address) {
        const normalizedAddress = ChainAnalytics.normalizeAddress(address);
        const payments = [];
        
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                if (Array.isArray(tx)) {
                    const contractTx = tx.find(t => t.type === "CONTRACT_PAYMENT");
                    if (contractTx && 
                        (ChainAnalytics.normalizeAddress(contractTx.sender) === normalizedAddress ||
                         ChainAnalytics.normalizeAddress(contractTx.recipient) === normalizedAddress)) {
                        payments.push({
                            ...contractTx,
                            blockHeight: block.index
                        });
                    }
                } else if (tx.type === "CONTRACT_PAYMENT" &&
                          (ChainAnalytics.normalizeAddress(tx.sender) === normalizedAddress ||
                           ChainAnalytics.normalizeAddress(tx.recipient) === normalizedAddress)) {
                    payments.push({
                        ...tx,
                        blockHeight: block.index
                    });
                }
            }
        }
        return payments;
    }

    getContractPaymentsByContractId(contractId) {
        const payments = [];
        
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                if (Array.isArray(tx)) {
                    const contractTx = tx.find(t => 
                        t.type === "CONTRACT_PAYMENT" && 
                        t.contractId === contractId
                    );
                    if (contractTx) {
                        payments.push({
                            ...contractTx,
                            blockHeight: block.index
                        });
                    }
                } else if (tx.type === "CONTRACT_PAYMENT" && tx.contractId === contractId) {
                    payments.push({
                        ...tx,
                        blockHeight: block.index
                    });
                }
            }
        }
        return payments;
    }

    getAddressStats(address) {
        const history = this.getTransactionHistory(address);
        const totalSent = history
            .filter(tx => tx.type === 'SENT')
            .reduce((sum, tx) => sum + tx.amount, 0);
        const totalReceived = history
            .filter(tx => tx.type === 'RECEIVED')
            .reduce((sum, tx) => sum + tx.amount, 0);
        
        return {
            balance: this.getBalance(address),
            totalSent,
            totalReceived,
            transactionCount: history.length,
            firstSeen: history.length > 0 ? 
                Math.min(...history.map(tx => tx.timestamp)) : null,
            lastSeen: history.length > 0 ? 
                Math.max(...history.map(tx => tx.timestamp)) : null
        };
    }

    getActiveAddresses() {
        const addresses = new Set();
        const addressActivity = new Map();

        // Scan chain for all addresses and their last activity
        for (const block of this.chain) {
            for (const tx of block.transactions) {
                if (tx.sender) {
                    addresses.add(tx.sender);
                    addressActivity.set(tx.sender, tx.timestamp);
                }
                if (tx.recipient) {
                    addresses.add(tx.recipient);
                    addressActivity.set(tx.recipient, tx.timestamp);
                }
            }
        }

        // Convert to array with additional metadata
        const activeAddresses = Array.from(addresses).map(address => ({
            address,
            balance: this.getBalance(address),
            lastActivity: addressActivity.get(address),
            transactionCount: this.getTransactionHistory(address).length
        }));

        // Sort by last activity (most recent first)
        return activeAddresses.sort((a, b) => b.lastActivity - a.lastActivity);
    }
}

// Initialize analytics
const analytics = new ChainAnalytics();

const corsHeaders = {
    'Access-Control-Allow-Origin': '*', //['http://localhost:5173', '*'],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token',
    'Access-Control-Max-Age': '86400',
};

// Start metadata server
console.log('Starting METADATA Server on 2224...');
Bun.serve({
    port: 2224,
    routes: {
        '/': (req) => {
            return Response.json({ 
                message: 'Boost Chain Metadata Service',
                lastSync: analytics.lastSync ? 
                    new Date(analytics.lastSync).toISOString() : null
            }, { headers: corsHeaders });
        },

        '/balance': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            POST: async (req) => {
                try {
                    const { address } = await req.json();
                    const balance = analytics.getBalance(address);
                    return Response.json({ address, balance }, { headers: corsHeaders });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/history': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            POST: async (req) => {
                try {
                    const { address } = await req.json();
                    const history = analytics.getTransactionHistory(address);
                    return Response.json({ 
                        address, 
                        transactions: history 
                    }, { 
                        headers: corsHeaders 
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/last-transactions': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            POST: async (req) => {
                try {
                    const { address, limit = 10 } = await req.json();
                    const transactions = analytics.getLastTransactions(address, limit);
                    return Response.json({ 
                        address, 
                        transactions 
                    }, { 
                        headers: corsHeaders 
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/stats': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            POST: async (req) => {
                try {
                    const { address } = await req.json();
                    const stats = analytics.getAddressStats(address);
                    return Response.json({ 
                        address, 
                        stats 
                    }, { 
                        headers: corsHeaders 
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/sync': async (req) => {
            await analytics.syncChain();
            return Response.json({ 
                message: 'Chain synced',
                timestamp: new Date(analytics.lastSync).toISOString()
            }, { 
                headers: corsHeaders 
            });
        },

        '/chain': async (req) => {
            return Response.json({
                chain: analytics.chain,
                lastSync: analytics.lastSync ? new Date(analytics.lastSync).toISOString() : null
            }, {
                headers: corsHeaders
            });
        },


        '/active-addresses': (req) => {
            const url = new URL(req.url);
            const minBalance = parseFloat(url.searchParams.get('minBalance')) || 0;
            const limit = parseInt(url.searchParams.get('limit')) || 100;

            let addresses = analytics.getActiveAddresses()
                .filter(addr => addr.balance >= minBalance)
                .slice(0, limit);

            return Response.json({
                totalAddresses: addresses.length,
                lastSync: analytics.lastSync ?
                    new Date(analytics.lastSync).toISOString() : null,
                addresses
            }, {
                headers: corsHeaders
            });
        },

        '/explorer': async (req) => {
            const file = Bun.file('./explorer.html');
            return new Response(file, {
                headers: {
                    ...corsHeaders,
                    'Content-Type': 'text/html'
                }
            });
        },

        '/contract-payments': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            POST: async (req) => {
                try {
                    const { address, limit } = await req.json();
                    const payments = analytics.getContractPayments(address);
                    
                    // Apply limit if provided
                    const limitedPayments = limit ? payments.slice(0, limit) : payments;

                    return Response.json({ 
                        address,
                        totalPayments: payments.length,
                        payments: limitedPayments.map(payment => ({
                            type: payment.type,
                            amount: Number(payment.amount),
                            sender: payment.sender,
                            recipient: payment.recipient,
                            timestamp: payment.timestamp,
                            blockHeight: payment.blockHeight,
                            contractId: payment.contractId,
                            status: payment.status || 'COMPLETED'
                        }))
                    }, { 
                        headers: corsHeaders 
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/contract-payments/:contractId': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            },
            GET: async (req) => {
                try {
                    const contractId = req.params.contractId;
                    const payments = analytics.getContractPaymentsByContractId(contractId);

                    return Response.json({ 
                        contractId,
                        totalPayments: payments.length,
                        payments: payments.map(payment => ({
                            type: payment.type,
                            amount: Number(payment.amount),
                            sender: payment.sender,
                            recipient: payment.recipient,
                            timestamp: payment.timestamp,
                            blockHeight: payment.blockHeight,
                            status: payment.status || 'COMPLETED'
                        }))
                    }, { 
                        headers: corsHeaders 
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders 
                    });
                }
            }
        },

        '/*': {
            OPTIONS: (req) => {
                return new Response(null, {
                    headers: corsHeaders,
                    status: 204
                });
            }
        }
    }
});

// # Get balance
// curl -X POST http://localhost:2224/balance \
//   -H "Content-Type: application/json" \
//   -d '{"address": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDagZajhCJrQ7Izbl37/\nRv5P0cRJ5GzdDxS6ebuZqK0n+1Vcn1CMNz0FS66vz4HoB7UcuqgLt83x47F6pDYA\nBBXwSWr4Lr/eM/72E2ddcOV4DSTAYs6HyPWpRDL80M601F9LML+sCUg9yxSZ3+b3\nf1CFqgAv/gn9IO5i6n2Ln63jUsH9HuB2q2aM0k6+j6PHkFienwXlcLYLpXwRshMk\nzrKQPYIZO/dL/FtGJloKlLaHQOBS23o/JB6cQMHNlbUtXG8XaaTf4UPEctQzMYAx\nyiVVc75UEHIxKfT+EUFXYKQVdfqwBQG3o7Jy9y7510V7LqW5SvpYAN0zEOBLruqh\nkwIDAQAB\n-----END PUBLIC KEY-----\n"}'

// # Get transaction history
// curl -X POST http://localhost:2224/history \
//   -H "Content-Type: application/json" \
//   -d '{"address": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDagZajhCJrQ7Izbl37/\nRv5P0cRJ5GzdDxS6ebuZqK0n+1Vcn1CMNz0FS66vz4HoB7UcuqgLt83x47F6pDYA\nBBXwSWr4Lr/eM/72E2ddcOV4DSTAYs6HyPWpRDL80M601F9LML+sCUg9yxSZ3+b3\nf1CFqgAv/gn9IO5i6n2Ln63jUsH9HuB2q2aM0k6+j6PHkFienwXlcLYLpXwRshMk\nzrKQPYIZO/dL/FtGJloKlLaHQOBS23o/JB6cQMHNlbUtXG8XaaTf4UPEctQzMYAx\nyiVVc75UEHIxKfT+EUFXYKQVdfqwBQG3o7Jy9y7510V7LqW5SvpYAN0zEOBLruqh\nkwIDAQAB\n-----END PUBLIC KEY-----\n"}'

// # Get last transactions with limit
// curl -X POST http://localhost:2224/last-transactions \
//   -H "Content-Type: application/json" \
//   -d '{
//     "address": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDagZajhCJrQ7Izbl37/\nRv5P0cRJ5GzdDxS6ebuZqK0n+1Vcn1CMNz0FS66vz4HoB7UcuqgLt83x47F6pDYA\nBBXwSWr4Lr/eM/72E2ddcOV4DSTAYs6HyPWpRDL80M601F9LML+sCUg9yxSZ3+b3\nf1CFqgAv/gn9IO5i6n2Ln63jUsH9HuB2q2aM0k6+j6PHkFienwXlcLYLpXwRshMk\nzrKQPYIZO/dL/FtGJloKlLaHQOBS23o/JB6cQMHNlbUtXG8XaaTf4UPEctQzMYAx\nyiVVc75UEHIxKfT+EUFXYKQVdfqwBQG3o7Jy9y7510V7LqW5SvpYAN0zEOBLruqh\nkwIDAQAB\n-----END PUBLIC KEY-----\n",
//     "limit": 5
//   }'

// # Get stats
// curl -X POST http://localhost:2224/stats \
//   -H "Content-Type: application/json" \
//   -d '{"address": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDagZajhCJrQ7Izbl37/\nRv5P0cRJ5GzdDxS6ebuZqK0n+1Vcn1CMNz0FS66vz4HoB7UcuqgLt83x47F6pDYA\nBBXwSWr4Lr/eM/72E2ddcOV4DSTAYs6HyPWpRDL80M601F9LML+sCUg9yxSZ3+b3\nf1CFqgAv/gn9IO5i6n2Ln63jUsH9HuB2q2aM0k6+j6PHkFienwXlcLYLpXwRshMk\nzrKQPYIZO/dL/FtGJloKlLaHQOBS23o/JB6cQMHNlbUtXG8XaaTf4UPEctQzMYAx\nyiVVc75UEHIxKfT+EUFXYKQVdfqwBQG3o7Jy9y7510V7LqW5SvpYAN0zEOBLruqh\nkwIDAQAB\n-----END PUBLIC KEY-----\n"}'
// curl http://localhost:2224/sync
// curl http://localhost:2224/active-addresses
// curl http://localhost:2224/active-addresses?minBalance=100
// curl http://localhost:2224/active-addresses?limit=10
// curl http://localhost:2224/active-addresses?minBalance=10&limit=50