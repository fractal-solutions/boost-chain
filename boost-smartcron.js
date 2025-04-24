//SMART CONTRACT SERVER
import { SmartContractManager } from "./smartContractManager.js";
import { SmartContract } from "./smartContract.js";
import { Transaction } from "./transaction.js";
import jwt from 'jsonwebtoken';
import { JWT_SECRET, ENCRYPTION_KEY } from './config.js';
process.env.NETWORK_SECRET = 'test-secret-123';



// Define CORS headers
const corsHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token',
    'Access-Control-Max-Age': '86400',
};

// Initialize contract manager
const contractManager = new SmartContractManager();

// Contract API Server
console.log('Starting SMART CONTRACT Server on 2223...')
Bun.serve({
    port: 2223,
    routes: {
        '/contract': {
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
                        `http://localhost:3001/balance?address=${encodeURIComponent(data.creator.publicKey)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                    );
                    const { balance } = await balanceRes.json();
                    console.log('Balance check:', { balance, required: requiredAmount });

                    // If insufficient balance, attempt deposit
                    if (balance < requiredAmount) {
                        console.log('Attempting deposit of:', requiredAmount);
                        const depositResult = await fetch('http://localhost:2222/deposit', {
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
                            `http://localhost:3001/balance?address=${encodeURIComponent(data.creator.publicKey)}`,
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
                        const txResult = await fetch('http://localhost:2222/txn', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${contractToken}`,
                                'x-auth-token': process.env.NETWORK_SECRET,
                                'x-contract-id': contract.contractId  // Add contract ID header
                            },
                            body: JSON.stringify({
                                from: {
                                    publicKey: contractData.creator.publicKey,
                                    privateKey: contractData.creator.privateKey // Include private key
                                },
                                to: contract.participants[0].publicKey,
                                amount: Number(contractData.amount),
                                type: 'CONTRACT_PAYMENT',
                                timestamp: transaction.timestamp,
                                signature: signature,
                                contractId: contract.contractId,  // Include contract ID in body
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
                            }, { headers: corsHeaders });
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
                        headers: corsHeaders 
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
            GET: async (req) => {
                const address = req.params.address;
                const contracts = contractManager.getContractsByParticipant(address);
                return Response.json({ contracts }, { headers: corsHeaders });
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
    const userResponse = await fetch('http://localhost:2225/user/by-public-key', {
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
        contractId: contract.contractId, // Include contract ID in token
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
}, 10000);