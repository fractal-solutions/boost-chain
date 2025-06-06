//SMART CONTRACT SERVER
import { SmartContractManager } from "./smartContractManager.js";
import { SmartContract } from "./smartContract.js";
import { Transaction } from "./transaction.js";
import jwt from 'jsonwebtoken';
import { JWT_SECRET, ENCRYPTION_KEY } from './config.js';
process.env.NETWORK_SECRET = 'test-secret-123';
import { smartcron_ip, chain_ip, users_ip } from "./config.js";
import { writeFileSync, existsSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';



// Update CORS headers definition
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token, x-contract-id',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
};

function handleOptions(req) {
    return new Response(null, {
        status: 204,
        headers: {
            ...corsHeaders,
            'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
        }
    });
}

function saveContracts(contracts) {
    try {
        const filePath = './data/contracts.json';
        const dataDir = dirname(filePath);

        // Create data directory if it doesn't exist
        if (!existsSync(dataDir)) {
            Bun.write(dataDir, '');
        }

        // Convert contracts to saveable format
        const data = contracts.map(contract => ({
            ...contract,
            // Convert Dates to timestamps
            startDate: contract.startDate, //|| contract.startDate?.getTime() 
            endDate:  contract.endDate, //|| contract.endDate?.getTime(),
            nextPaymentDate:  contract.nextPaymentDate //|| contract.nextPaymentDate?.getTime(),
        }));

        writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
        console.log(`Saved ${data.length} contracts to ${filePath}`);
    } catch (error) {
        console.error('Error saving contracts:', error);
    }
}

function loadContracts() {
    try {
        const filePath = './data/contracts.json';
        if (!existsSync(filePath)) {
            console.log('No existing contracts file found');
            return [];
        }

        const data = JSON.parse(readFileSync(filePath, 'utf8'));
        console.log(`Loaded ${data.length} contracts from ${filePath}`);
        return data;
    } catch (error) {
        console.error('Error loading contracts:', error);
        return [];
    }
}

// Initialize contract manager
const contractManager = new SmartContractManager();

// Load existing contracts
const savedContracts = loadContracts();
savedContracts.forEach(contractData => {
    try {
        contractManager.createContract({
            ...contractData,
            // Convert timestamps back to Dates
            startDate: new Date(contractData.startDate),
            endDate: new Date(contractData.endDate),
            nextPaymentDate: new Date(contractData.nextPaymentDate)
        });
    } catch (error) {
        console.error('Error restoring contract:', error);
    }
});

// Contract API Server
console.log('Starting SMART CONTRACT Server on 2223...')
Bun.serve({
    hostname: '0.0.0.0',
    port: 2223,
    routes: {
        '/contract': {
            OPTIONS: async (req) => {
                // Handle preflight request
                return new Response(null, {
                    status: 204,
                    headers: {
                        ...corsHeaders,
                        'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
                    }
                });
            },
            POST: async (req) => {
                try {
                    const userToken = req.headers.get('authorization');
                    if (!userToken) {
                        throw new Error('Missing user authentication');
                    }
                    // Parse and validate request body
                    let data;
                    try {
                        const text = await req.text();
                        //console.log('Raw request body:', text);
                        data = JSON.parse(text);
                        console.log('Parsed request body:', data);
                    } catch (error) {
                        console.error('JSON parse error:', error);
                        return Response.json({
                            success: false,
                            error: 'Invalid JSON format in request body'
                        }, { 
                            status: 400,
                            headers: corsHeaders 
                        });
                    }

                    // Check balance and handle deposit if needed
                    const fee = Number(data.amount) * 0.01;
                    const requiredAmount = Number(data.amount) + fee;
                    
                    // Check current balance
                    const balanceRes = await fetch(
                        `http://127.0.0.1:3001/balance?address=${encodeURIComponent(data.creator.publicKey)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                    );
                    const { balance } = await balanceRes.json();
                    console.log('Balance check:', { balance, required: requiredAmount });

                    // If insufficient balance, attempt deposit
                    if (balance < requiredAmount) {
                        console.log('Attempting deposit of:', requiredAmount);
                        const depositResult = await fetch(`${chain_ip}/deposit`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${userToken}`, // Use the user's token
                                'x-auth-token': process.env.NETWORK_SECRET
                            },
                            body: JSON.stringify({
                                to: data.creator.publicKey,
                                amount: Math.ceil(requiredAmount) // Round up to ensure sufficient funds
                            })
                        });
                    
                        if (!depositResult.ok) {
                            const depositError = await depositResult.text();
                            console.error('Deposit failed:', depositError);
                            throw new Error(`Failed to deposit required funds: ${depositError}`);
                        }
                    
                        // Verify the deposit was successful
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        const newBalanceRes = await fetch(
                            `http://127.0.0.1:3001/balance?address=${encodeURIComponent(data.creator.publicKey)}`,
                            { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                        );
                        const { balance: newBalance } = await newBalanceRes.json();
                        console.log('New balance after deposit:', newBalance);
                    
                        if (newBalance < requiredAmount) {
                            throw new Error(`Deposit failed to provide sufficient balance. Required: ${requiredAmount}, Available: ${newBalance}`);
                        }
                    }

                    // Format contract data
                    const contractData = {
                        creator: {
                            publicKey: data.creator.publicKey,
                            privateKey: data.creator.privateKey,
                            type: 'USER',
                            authToken: userToken
                        },
                        participants: data.participants.map(p => ({
                            publicKey: p,
                            type: 'USER'
                        })),
                        amount: Number(data.amount),
                        interval: Number(data.interval),
                        endDate: Number(data.endDate),
                        startDate: Date.now(),
                        status: 'ACTIVE',
                        type: data.type || 'RECURRING_PAYMENT'
                    };

                    // Create contract
                    const contract = contractManager.createContract(contractData);

                    // Create and sign transaction
                    //Update to handle multiple participants
                    const transaction = new Transaction(
                        contractData.creator.publicKey,
                        contract.participants[0].publicKey,
                        Number(contractData.amount),
                        Date.now(),
                        'CONTRACT_PAYMENT',
                    );
                    const contractToken = await generateContractToken({
                        ...contractData,
                        contractId: contract.contractId // Add contract ID to token generation
                    });

                    // Sign transaction with creator's private key
                    try {
                        const signature = transaction.signTransaction(contractData.creator.privateKey);

                        // Log the signature for inspection
                        console.log('Generated signature:', signature);

                        // Execute initial transaction
                        const txResult = await fetch(`${chain_ip}/txn`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${contractToken}`,
                                'x-auth-token': process.env.NETWORK_SECRET,
                                'x-contract-id': contract.contractId 
                            },
                            body: JSON.stringify({
                                from: {
                                    publicKey: contractData.creator.publicKey,
                                    privateKey: contractData.creator.privateKey 
                                },
                                to: contract.participants[0].publicKey,
                                amount: Number(contractData.amount),
                                type: 'CONTRACT_PAYMENT',
                                timestamp: transaction.timestamp,
                                signature: signature,
                                contractId: contract.contractId,  
                                token: contractToken,
                            })
                        });

                        // Handle response
                        try {
                            const txResponse = await txResult.text(); // Get raw response first
                            const parsedResponse = JSON.parse(txResponse);
                            console.log('Transaction response:', parsedResponse);
                            
                            if (!txResult.ok) {
                                throw new Error(`Failed to process initial contract payment: ${parsedResponse.error || 'Unknown error'}`);
                            }
                            
                            return Response.json({
                                success: true,
                                contractId: contract.contractId,
                                nextPaymentDate: contract.nextPaymentDate
                            }, { 
                                headers: {
                                    ...corsHeaders,
                                    'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
                                }
                            });
                        } catch (error) {
                            console.error('Transaction response error:', error);
                            throw new Error(`Transaction failed: ${error.message}`);
                        }
                    } catch (signError) {
                        console.error('Signature creation error:', signError);
                        throw new Error(`Failed to sign transaction: ${signError.message}`);
                    }

                } catch (error) {
                    console.error('Contract creation error:', error);
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { 
                        status: 400,
                        headers: {
                            ...corsHeaders,
                            'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
                        }
                    });
                }
            }
        },

        /*curl -X POST http://localhost:2223/contract \
        -H "Content-Type: application/json" \
        -d '{
            "creator": {
                "publicKey": "alice_public_key",
                "privateKey": "alice_private_key"
            },
            "participants": ["bob_public_key"],
            "amount": 100,
            "interval": 604800000,
            "startDate": "2024-03-26T00:00:00.000Z",
            "endDate": "2024-06-26T00:00:00.000Z",
            "terms": {
                "paymentMethod": "BOOST",
                "penalties": {
                    "lateFee": 10
                }
            }
        }' */

        '/contract/:id': {
            OPTIONS: handleOptions,
          // Get contract details
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { 
                        status: 404,
                        headers: corsHeaders 
                    });
                }
                return Response.json(contract, { headers: corsHeaders });
            },

            DELETE: async (req) => {
                try {
                    const id = req.params.id;
                    const result = contractManager.terminateContract(id);
                    return Response.json({
                        success: true,
                        terminationDetails: result
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

        '/contract/:id/payments': {
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { 
                        status: 404,
                        headers: corsHeaders 
                    });
                }
                return Response.json(contract.paymentHistory, { headers: corsHeaders });
            }
        },

        '/contracts/user/:address': {
            OPTIONS: handleOptions,
            GET: async (req) => {
                try {
                    const address = req.params.address;
                    console.log('Searching contracts for address:', address);
                    
                    // Log all contracts for debugging
                    const allContracts = contractManager.getAllContracts();
                    console.log('All contracts:', allContracts.map(c => ({
                        id: c.contractId,
                        creator: c.creator.publicKey,
                        participants: c.participants.map(p => p.publicKey),
                        status: c.status
                    })));
                    
                    const contracts = contractManager.getContractsByParticipant(address);
                    console.log('Found contracts:', contracts);

                    return Response.json(
                        { 
                            success: true,
                            contracts,
                            searchedAddress: address 
                        }, 
                        { 
                            headers: {
                                ...corsHeaders,
                                'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
                            }
                        }
                    );
                } catch (error) {
                    console.error('Error fetching contracts:', error);
                    return Response.json(
                        { 
                            success: false,
                            error: error.message,
                            searchedAddress: req.params.address 
                        }, 
                        { 
                            status: 400,
                            headers: {
                                ...corsHeaders,
                                'Access-Control-Allow-Origin': req.headers.get('Origin') || '*'
                            }
                        }
                    );
                }
            }
        },

        '/contract/:id/status': {
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { 
                        status: 404,
                        headers: corsHeaders 
                    });
                }
                return Response.json(contract.getStatus(), { headers: corsHeaders });
            }
        },
        
        '/debug/contracts': {
            GET: async () => {
                const allContracts = contractManager.getAllContracts();
                return Response.json({
                    success: true,
                    count: allContracts.length,
                    contracts: allContracts.map(c => ({
                        id: c.contractId,
                        creator: c.creator.publicKey,
                        participants: c.participants.map(p => p.publicKey),
                        status: c.status,
                        amount: c.amount,
                        nextPaymentDate: c.nextPaymentDate
                    }))
                }, {
                    headers: {
                        ...corsHeaders,
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        },

        '/*': {
            OPTIONS: handleOptions
        }
    }
});

// Batch process payments
async function processBatchPayments(contracts) {
    const batchSize = 5;
    for (let i = 0; i < contracts.length; i += batchSize) {
        const batch = contracts.slice(i, i + batchSize);
        await Promise.all(batch.map(contract => 
            contractManager.executeScheduledPayment(contract)
        ));
    }
}

async function generateContractToken(contract) {
    // Get user info from boost-users service
    const userResponse = await fetch(`${users_ip}/user/by-public-key`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            publicKey: contract.creator.publicKey
        })
    });

    const rawResponse = await userResponse.text();
    console.log('Raw user response:', rawResponse);

    if (!userResponse.ok) {
        throw new Error('Failed to fetch user information');
    }

    const userData = JSON.parse(rawResponse);
    if (!userData.success) {
        throw new Error(userData.error || 'User not found');
    }

    // Calculate token expiration
    const now = Date.now();
    const endDate = Number(contract.endDate);
    const secondsUntilEnd = Math.floor((endDate - now) / 1000);
    const expiresIn = Math.min(Math.max(secondsUntilEnd, 60), 365 * 24 * 60 * 60);

    return jwt.sign({
        id: userData.data.id,
        role: userData.data.role,
        publicKey: userData.data.publicKey,
        contractId: contract.contractId, 
        permissions: ['execute_contract_payment']
    }, JWT_SECRET, { expiresIn });
}

setInterval(async () => {
    const contracts = contractManager.getAllContracts();
    const batchContracts = contracts
        .filter(c => c.status === 'ACTIVE' && 
                Date.now() >= new Date(c.nextPaymentDate).getTime());
    console.log('Checking for scheduled payments...');
    console.log('Contracts:', contracts.map(contract => ({
        contractId: contract.contractId,
        creator: contract.creator.publicKey,
        participants: contract.participants.map(p => p.publicKey),
        amount: contract.amount,
        status: contract.status,
        nextPaymentDate: contract.nextPaymentDate,
        endDate: contract.endDate,
    })));
    await processBatchPayments(batchContracts);
    
    // Save contracts after processing payments
    if (batchContracts.length > 0) {
        saveContracts(contracts);
    }
}, 10000);

// Add save interval (every 5 minutes)
setInterval(() => {
    const contracts = contractManager.getAllContracts();
    saveContracts(contracts);
}, 5 * 60 * 1000);

// Add shutdown handlers
process.on('SIGINT', () => {
    console.log('Saving contracts before shutdown...');
    const contracts = contractManager.getAllContracts();
    saveContracts(contracts);
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('Saving contracts before shutdown...');
    const contracts = contractManager.getAllContracts();
    saveContracts(contracts);
    process.exit(0);
});