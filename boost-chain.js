import { Node, NodeType, generateKeyPair } from "./node.js";
import { Transaction } from "./transaction.js";
import { createHmac, randomBytes } from "crypto";
import { authenticateToken, requireRole, requirePermission } from './middleware.js';
import { ROLES } from './roles.js';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from './config.js'; 
import { writeFile, readFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { ChainStorage } from './chainStorage.js';

const DATA_DIR = './data';
const CHAIN_FILE = path.join(DATA_DIR, 'chain.json');
const SAVE_INTERVAL = 60000; // 1 minute in milliseconds

// Create test accounts
const alice = generateKeyPair();
const bob = generateKeyPair();
const charlie = generateKeyPair();
const dave = generateKeyPair();

process.env.NETWORK_SECRET = 'test-secret-123';

let chainState;
async function displayChainState(nodePort, message) {
    console.log(`\n${message}`);
    try {
        const response = await fetch(`http://localhost:${nodePort}/chain`, {
            headers: { 'x-auth-token': process.env.NETWORK_SECRET }
        });
        
        let chain = await response.json();
        
        // Handle both array and object formats
        if (!Array.isArray(chain)) {
            console.log('Converting chain object to array...');
            // If chain is an object with numeric keys, convert to array
            chain = Object.values(chain).map(block => {
                // Ensure block has all required properties
                if (!block || !block.transactions || !block.hash) {
                    console.log('Invalid block structure:', block);
                    return null;
                }
                return {
                    index: block.index,
                    transactions: block.transactions,
                    hash: block.hash,
                    previousHash: block.previousHash,
                    timestamp: block.timestamp,
                    nonce: block.nonce
                };
            }).filter(block => block !== null);
        }

        // Display chain information
        // Only show last 10 blocks
        const startIndex = Math.max(0, chain.length - 10);
        for (let i = startIndex; i < chain.length; i++) {
            const block = chain[i];
            console.log(`\n📦 Block #${block.index}`);
            console.log(`├─ Transactions: ${block.transactions.length}`);
            console.log(`└─ Hash: ${block.hash.substring(0, 10)}...`);

            // Show transaction details
            block.transactions.forEach((tx, index) => {
                // Extract meaningful part of public keys
                const senderKey = tx.sender?.replace('-----BEGIN PUBLIC KEY-----\n', '')
                                         .replace('\n-----END PUBLIC KEY-----', '')
                                         .trim();
                const recipientKey = tx.recipient?.replace('-----BEGIN PUBLIC KEY-----\n', '')
                                               .replace('\n-----END PUBLIC KEY-----', '')
                                               .trim();

                const formattedSenderKey = senderKey ? `${senderKey.substring(0,8)}...${senderKey.substring(senderKey.length-8)}` : '';
                const formattedRecipientKey = recipientKey ? `${recipientKey.substring(0,8)}...${recipientKey.substring(recipientKey.length-8)}` : '';

                console.log(`   Transaction #${index + 1}`);
                console.log(`   ├─ Type: ${tx.amount > 0 ? 'Transfer' : 'System'}`);
                console.log(`   ├─ From: ${senderKey ? `${formattedSenderKey}` : 'SYSTEM'}`);
                console.log(`   ├─ To:   ${recipientKey ? `${formattedRecipientKey}` : 'SYSTEM'}`);
                console.log(`   └─ Amount: ${tx.amount} tokens`);
            });
            return chain;
        }
    } catch (error) {
        console.error('Error displaying chain state:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
        return error;
    }
}

async function checkAllBalances(nodePort) {
    console.log('\nAccount Balances:');
    const accounts = [alice, bob, charlie, dave];

    for (const account of accounts) {
        try {
            const balanceRes = await fetch(
                `http://localhost:${nodePort}/balance?address=${encodeURIComponent(account.publicKey)}`,
                { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
            );
            
            if (balanceRes.status === 429) {
                console.log('Rate limit hit, trying alternate node...');
                // Try another node
                for (const altPort of [3001, 3002, 3003, 3004]) {
                    if (altPort === nodePort) continue;
                    const altRes = await fetch(
                        `http://localhost:${altPort}/balance?address=${encodeURIComponent(account.publicKey)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                    );
                    if (altRes.ok) {
                        const { balance } = await altRes.json();
                        const shortKey = account.publicKey
                            .replace('-----BEGIN PUBLIC KEY-----\n', '')
                            .replace('\n-----END PUBLIC KEY-----\n', '')
                            .substring(0, 8);
                        console.log(`${shortKey}... : ${balance} tokens`);
                        break;
                    }
                }
            } else {
                const { balance } = await balanceRes.json();
                const shortKey = account.publicKey
                    .replace('-----BEGIN PUBLIC KEY-----\n', '')
                    .replace('\n-----END PUBLIC KEY-----\n', '')
                    .substring(0, 8);
                console.log(`${shortKey}... : ${balance} tokens`);
            }
        } catch (error) {
            console.error('Error fetching balance:', error.message);
        }
    }
}

async function sendTransaction(from, to, amount, nodePort, type = "TRANSACTION") {
    try {
        let txData;
        const fee = 0.01 * amount;
        const totalAmount = amount + fee;
        // Always send deposits and withdrawals to controller node (3001)
        const targetPort = type === "DEPOSIT" || type === "WITHDRAW" || type === "CONTRACT_PAYMENT" ? 3001 : 3001;//nodePort;
        
        // Handle CONTRACT_PAYMENT type specifically
        if (type === "CONTRACT_PAYMENT") {
            const balanceRes = await fetch(
                `http://localhost:${targetPort}/balance?address=${encodeURIComponent(from.publicKey)}`,
                { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
            );
            const { balance } = await balanceRes.json();
            
            if (balance < totalAmount) {
                return {
                    error: `Insufficient balance for transaction + fee. Required: ${totalAmount}, Available: ${balance}`,
                    balance,
                    attempted: totalAmount
                };
            }
        
            // Create both main transaction and fee transaction
            const transaction = new Transaction(from.publicKey, to.publicKey, amount, Date.now(), "CONTRACT_PAYMENT");
            transaction.signTransaction(from.privateKey);
            
            const nodePublicKey = await getNodePublicKey(targetPort);
            const fee = new Transaction(from.publicKey, nodePublicKey, 0.01 * amount, Date.now(), "FEE");
            fee.signTransaction(from.privateKey);
        
            txData = {
                transactions: [
                    {
                        sender: from.publicKey,
                        recipient: to.publicKey,
                        amount: Number(amount),
                        timestamp: transaction.timestamp,
                        signature: transaction.signature,
                        type: "CONTRACT_PAYMENT"
                    },
                    {
                        sender: from.publicKey,
                        recipient: nodePublicKey,
                        amount: Number(fee.amount),
                        timestamp: fee.timestamp,
                        signature: fee.signature,
                        type: "FEE"
                    }
                ]
            };
        } else if (type === "DEPOSIT") {
            const timestamp = Date.now();
            const nonce = randomBytes(16).toString('hex');
            
            // Create authorization signature
            const message = `${to.publicKey}:${amount}:${timestamp}:${nonce}`;
            const authorization = createHmac('sha256', process.env.NETWORK_SECRET)
                .update(message)
                .digest('hex');

            txData = {
                sender: null,
                recipient: to.publicKey,
                amount: amount,
                timestamp: timestamp,
                nonce: nonce,
                authorization: authorization,
                type: "DEPOSIT"
            };
        } else if (type === "WITHDRAW") {
            const timestamp = Date.now();
            const nonce = randomBytes(16).toString('hex');

            // Create both authorization and transaction signature
            const message = `${from.publicKey}:${amount}:${timestamp}:${nonce}`;
            const authorization = createHmac('sha256', process.env.NETWORK_SECRET)
                .update(message)
                .digest('hex');

            // Create and sign transaction
            const transaction = new Transaction(from.publicKey, null, amount);
            transaction.timestamp = timestamp;
            transaction.signTransaction(from.privateKey);

            txData = {
                sender: from.publicKey,
                recipient: null,  // Null recipient for withdrawals
                amount: amount,
                timestamp: timestamp,
                nonce: nonce,
                authorization: authorization,
                type: "WITHDRAW",
                signature: transaction.signature 
                
            };
        } else {
            // For non-DEPOSIT/WITHDRAW transactions i.e TRANSFER, check if sender has enough balance for both amount and fee
            if (from !== null && type !== "DEPOSIT" && type !== "WITHDRAW") {
                const balanceRes = await fetch(
                    `http://localhost:${targetPort}/balance?address=${encodeURIComponent(from.publicKey)}`,
                    { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                );
                const { balance } = await balanceRes.json();
                
                if (balance < totalAmount) {
                    return {
                        error: "Insufficient balance for transaction + fee",
                        balance,
                        attempted: totalAmount
                    };
                }
            }

            // transaction needs signing
            console.log(from);
            const transaction = new Transaction(from.publicKey, to.publicKey, amount);
            transaction.signTransaction(from.privateKey); 
            const nodePublicKey = await getNodePublicKey(targetPort);
            const fee = new Transaction(from.publicKey, nodePublicKey, 0.01 * amount);
            fee.signTransaction(from.privateKey);
            const feeData = {
                sender: from.publicKey !== null ? from.publicKey : null,
                recipient: nodePublicKey,
                amount: fee.amount,
                timestamp: transaction.timestamp,
                signature: fee.signature,
                type: "FEE"
            };
                 
            const transactionData = {
                sender: from.publicKey,
                recipient: to.publicKey,
                amount: amount,
                timestamp: transaction.timestamp,
                signature: transaction.signature,
                type: "TRANSFER"
            };

            txData = {
                transactions: [transactionData, feeData].map(tx => ({
                    sender: tx.sender,
                    recipient: tx.recipient,
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    type: tx.type,
                    signature: tx.signature
                }))
            }
        }
     
        console.log(`Sending ${type} transaction to port ${targetPort}`);
        const txResponse = await fetch(`http://localhost:${targetPort}/transaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': process.env.NETWORK_SECRET
            },
            body: JSON.stringify({
                ...txData,
                type: type === "CONTRACT_PAYMENT" ? "CONTRACT_PAYMENT" : txData.type
            })
        });

        const result = await txResponse.json();

        if (!txResponse.ok) {
            throw new Error(`Transaction failed: ${result.error}`);
        }

        // Wait for mining and synchronization
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Only try to format address if 'from' exists
        const fromAddress = from ? formatAddress(from.publicKey) : 'DEPOSIT';
        // Adjust message based on transaction type
        if (type === "DEPOSIT") {
            console.log(`Transaction successful: ${amount} tokens deposited to ${formatAddress(to.publicKey)}`);
        } else if (type === "WITHDRAW") {
            console.log(`Transaction successful: ${amount} tokens withdrawn from ${fromAddress}`);
        } else {
            console.log(`Transaction successful: ${amount} tokens sent from ${fromAddress}`);
        }
        return result;
    } catch (error) {
        console.error('Transaction error:', error.message);
        return { error: error.message };
    }
}

async function getNodePublicKey(nodePort) {
    try {
        const response = await fetch(`http://localhost:${nodePort}/get-key`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': process.env.NETWORK_SECRET
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data.publicKey;
    } catch (error) {
        console.error('Error getting node public key:', error);
        throw error;
    }
}

async function checkNodesHealth(nodes) {
    console.log('\x1b[33m%s\x1b[0m', '\n===========================================');
    console.log('\x1b[33m%s\x1b[0m', 'Checking health of all nodes...');
    let allHealthy = true;
    
    for (let i = 0; i < nodes.length; i++) {
        const port = 3001 + i;
        try {
            const response = await fetch(`http://localhost:${port}/health`, {
                headers: { 'x-auth-token': process.env.NETWORK_SECRET }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const health = await response.json();
            
            console.log('\x1b[33m%s\x1b[0m', `┌─ Node ${i + 1} (port ${port}) ───────────────────`);
            console.log(`\x1b[33m%s\x1b[0m`, `│ Status: ${health.status === 'healthy' ? '\x1b[32m' : '\x1b[31m'}${health.status || 'undefined'}\x1b[33m`);
            console.log('\x1b[33m%s\x1b[0m', `│ Type: ${health.nodeType}`); 
            console.log('\x1b[33m%s\x1b[0m', `│ Blocks: ${health.blockHeight || 0} (${(health.blockHeight || 1) - 1} transactions processed)`);
            console.log('\x1b[33m%s\x1b[0m', `│ Connected Peers: ${health.peersCount || 0}`);
            console.log('\x1b[33m%s\x1b[0m', `└ Pending Transactions: ${health.pendingTransactions || 0}`);
            
            if (health.status !== 'healthy') {
                allHealthy = false;
                console.log('\x1b[31m%s\x1b[0m', `  WARNING: Node is unhealthy!`);
            }
        } catch (error) {
            allHealthy = false;
            console.log('\x1b[31m%s\x1b[0m', `Node ${i + 1} (port ${port}): OFFLINE or ERROR`);
            console.log('\x1b[31m%s\x1b[0m', `  Error details: ${error.message}`);
        }
    }
    console.log('\x1b[33m%s\x1b[0m', '===========================================\n');
    
    return allHealthy;
}

function formatAddress(publicKey) {
    // Skip the header/footer and get just the key portion
    const cleanKey = publicKey
        .replace('-----BEGIN PUBLIC KEY-----\n', '')
        .replace('\n-----END PUBLIC KEY-----', '')
        .trim();
    
    // Take first 8 characters for a readable preview
    return cleanKey.substring(0, 8) + '...';
}

async function main() {
    // Load existing chain if available
    const existingChainData = await ChainStorage.loadChain();
    console.log('Loading existing chain data:', existingChainData ? 'Found' : 'Not found');

    // Initial balances (only used if no existing chain)
    const genesisBalances = {
        [alice.publicKey]: 1000,
        [bob.publicKey]: 500,
        [charlie.publicKey]: 750,
        [dave.publicKey]: 250
    };

    // Start controller node first
    const controllerNode = await new Node({
        host: 'localhost',
        port: 3001,
        nodeType: NodeType.CONTROLLER,
        seedNodes: [],
        genesisBalances,
        existingChain: existingChainData
    }).initialize();

    // Wait for controller node to be fully initialized
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Start other nodes with the same chain data
    const nodes = [controllerNode];
    
    // Wait for main node to be ready
    await new Promise(resolve => setTimeout(resolve, 4000));
 
    // Start SME nodes
    const smeNodes = await Promise.all([
        new Node({
            host: 'localhost',
            port: 3002,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001'],
            genesisBalances,
            businessInfo: {
                    name: "SME_1",
                    industry: "Retail",
                    established: "2020"
            }
        }).initialize(),
        new Node({
            host: 'localhost',
            port: 3003,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001', 'localhost:3002'],
            genesisBalances,
            businessInfo: {
                    name: "SME_2",
                    industry: "Services",
                    established: "2019"
            }
        }).initialize(),
        new Node({
            host: 'localhost',
            port: 3004,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001','localhost:3002','localhost:3003'],
            genesisBalances,
            businessInfo: {
                    name: "SME_3",
                    industry: "Manufacturing",
                    established: "2018"
            }
        }).initialize(),
        new Node({
            host: 'localhost',
            port: 3005,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001','localhost:3002','localhost:3003','localhost:3004'],
            genesisBalances,
            businessInfo: {
                    name: "SME_4",
                    industry: "Technology",
                    established: "2017"
            }
        }).initialize(),
        new Node({
            host: 'localhost',
            port: 3006,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001','localhost:3002','localhost:3003','localhost:3004','localhost:3005'],
            genesisBalances,
            businessInfo: {
                    name: "SME_5",
                    industry: "Finance",
                    established: "2016"
            }
        }).initialize(),
        new Node({
            host: 'localhost',
            port: 3007,
            nodeType: NodeType.SME,
            seedNodes: ['localhost:3001','localhost:3002','localhost:3003','localhost:3004','localhost:3005','localhost:3006'],
            genesisBalances,
            businessInfo: {
                    name: "SME_6",
                    industry: "Healthcare",
                    established: "2015"
            }
        }).initialize()
    ]);

    // Start validator node
    const validatorNode = await new Node({
        host: 'localhost',
        port: 3008,
        nodeType: NodeType.VALIDATOR,
        seedNodes: ['localhost:3001'],
        genesisBalances
    }).initialize();

    
    nodes.push(...smeNodes, validatorNode);
    
    // Wait for all nodes to connect
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Display initial state
    chainState = await displayChainState(3001, 'Initial blockchain state:');
    await checkAllBalances(3001);

    // Series of transactions
    const transactions = [
        { from: null, to: alice, amount: 1000, message: 'Controller node deposits 1000 to Alice', type: "DEPOSIT" },
        { from: alice, to: null, amount: 100, message: 'Alice withdraws 100', type: "WITHDRAW" },
        { from: alice, to: bob, amount: 100, message: 'Alice sends 100 to Bob', type: "TRANSFER" },
        { from: bob, to: charlie, amount: 50, message: 'Bob sends 50 to Charlie', type: "TRANSFER" },
        // { from: alice, to: charlie, amount: 150, message: 'Alice sends 150 to Charlie', type: "TRANSACTION" },
        // { from: bob, to: dave, amount: 200, message: 'Bob sends 200 to Dave', type: "TRANSACTION" }
    ];

    let count = 0;
    while (count < 1) {
    // Execute each transaction
        for (const tx of transactions) {
            console.log('\n' + '='.repeat(80) + '\n');
            console.log('\x1b[34m%s\x1b[0m', `\nExecuting transaction: ${tx.message}`);
            const ports = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008];
            const randomPort = ports[Math.floor(Math.random() * ports.length)];
            const result = await sendTransaction(tx.from, tx.to, tx.amount, randomPort, tx.type);
            
            if (result.error) {
                console.log('\x1b[31m%s\x1b[0m', `Transaction failed: ${result.error}`);
                if (result.balance !== undefined) {
                    console.log('\x1b[31m%s\x1b[0m', `Available balance: ${result.balance}, Attempted: ${result.attempted}`);
                }
            } else {
                console.log('\x1b[32m%s\x1b[0m', 'Transaction successful');
            }
            console.log('\n' + '='.repeat(80) + '\n');
            
            //await new Promise(resolve => setTimeout(resolve, 2000));
                //await displayChainState(3001, 'Updated blockchain state:');
            //await new Promise(resolve => setTimeout(resolve, 2000));
                await checkAllBalances(3001);
            //await new Promise(resolve => setTimeout(resolve, 2000));
            // Wait a bit between transactions regardless of success/failure
            await new Promise(resolve => setTimeout(resolve, 2000));
            // Check mining rewards
            console.log('\nNode Balances:');
            for (const port of [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008]) {
                const node = nodes[port - 3001];
                const balance = await fetch(`http://localhost:${port}/balance?address=${encodeURIComponent(node.wallet.publicKey)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                        ).then(res => res.json()).then(data => data.balance);
                console.log(`Node ${port}: ${balance} tokens (from mining)`);
            }
            
        }

        //const healthCheckInterval = setInterval(() => checkNodesHealth(nodes), 60000); // Every minute
        await checkNodesHealth(nodes);
        chainState = await displayChainState(3001, "Chain: ")
        await new Promise(resolve => setTimeout(resolve, 1000));
        // Start new validator node
        console.log(`\n${'-'.repeat(30)}\nStarting new validator node on port ${3005 + count}\n${'-'.repeat(30)}`);
        const newNode = await new Node({
            host: 'localhost',
            port: 3009 + count,
            nodeType: NodeType.VALIDATOR,
            seedNodes: ['localhost:3001'],
            genesisBalances
        }).initialize();
        count++;
        await new Promise(resolve => setTimeout(resolve, 2000));
        console.log('\nTransaction series complete. Monitoring node health...');
        console.log('Press Ctrl+C to exit.');
    }

    // Handle cleanup on exit
    process.on('SIGINT', async () => {
        // Save chain one last time before exiting
        if (controllerNode) {
            await ChainStorage.saveChain(controllerNode.blockchain);
            controllerNode.cleanup();
        }
        console.log('\nStopping nodes and saving chain state...');
        process.exit();
    });
}

main().catch(console.error); 

//Boost-Chain Server
const corsHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token',
    'Access-Control-Max-Age': '86400',
};

const baseHeaders = {
    ...corsHeaders,
    'Content-Type': 'application/json'
  };
console.log('Starting BOOST CHAIN Server on 2222...');
const server = Bun.serve({
    port: 2222,
    routes: {
        '/': (req) => {	
            return Response.json({ message: 'Welcome to Boost-Chain' });
        },
        '/chain': {
            GET: async (req) => {
                // const auth = requirePermission('view_chain')(req);
                // if (!auth.authenticated) {
                //     return Response.json({ error: auth.error }, { status: auth.status });
                // }
                let chain = await displayChainState(3001, "FETCH CHAIN: ");
                return Response.json({ chain });
            }
        },
        '/txn': { 
            POST: async (req) => {
                const body = await req.json();

                if (body.type === 'CONTRACT_PAYMENT') {
                    // Calculate total amount including fee
                    const fee = body.amount * 0.01; // 1% fee
                    const totalAmount = Number(body.amount) + fee;
                
                    // Check balance - Fix the from address extraction
                    const fromAddress = body.from.publicKey || body.from;
                    const balanceRes = await fetch(
                        `http://localhost:3001/balance?address=${encodeURIComponent(fromAddress)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                    );
                    const { balance } = await balanceRes.json();
                    console.log('Contract Payment Balance Check:', {
                        address: fromAddress.substring(0, 32) + '...',
                        balance,
                        required: totalAmount,
                        fee
                    });
                
                    if (balance < totalAmount) {
                        return Response.json({ 
                            error: `Insufficient balance for transaction + fee. Required: ${totalAmount}, Available: ${balance}`,
                            balance,
                            attempted: totalAmount
                        }, { 
                            status: 400,
                            headers: corsHeaders 
                        });
                    }
      
                    const token = req.headers.get('authorization')?.split(' ')[1];
                    const contractId = req.headers.get('x-contract-id');
                    if (!token) {
                        return Response.json({ 
                            error: 'No token provided' 
                        }, { 
                            status: 401,
                            headers: corsHeaders 
                        });
                    }

                    try {
                        // Verify contract token
                        const decoded = jwt.verify(token, JWT_SECRET || process.env.NETWORK_SECRET);
        
                        if (!decoded.permissions?.includes('execute_contract_payment')) {
                            throw new Error('Invalid contract permissions');
                        }
                
                        // Check both contract ID in token and header
                        if (!decoded.contractId || !contractId || decoded.contractId !== contractId) {
                            throw new Error('Contract ID mismatch');
                        }

                        // Additional contract validation
                        if (decoded.contractId !== req.headers.get('x-contract-id')) {
                            throw new Error('Contract ID mismatch');
                        }
                    } catch (error) {
                        return Response.json({ 
                            error: error.message 
                        }, { 
                            status: 401,
                            headers: corsHeaders 
                        });
                    }
                } else {
                    // Regular transaction authentication
                    const auth = requirePermission('transfer')(req);
                    if (!auth.authenticated) {
                        return Response.json({ 
                            error: auth.error 
                        }, { 
                            status: auth.status,
                            headers: corsHeaders 
                        });
                    }
                }

                // Continue with transaction processing
                try {
                    const { from, to, amount, type } = body;
                    const tx = { from, to, amount, type };
                    const result = await received_transaction(tx);

                    // Send Recipient a notification 
                    const publicKeyResponse = await fetch('http://localhost:2225/user/by-public-key', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ publicKey: to })
                      });
                    const publicKeyData = await publicKeyResponse.json();
                      if (!publicKeyData.success) {
                        throw new Error('Failed to fetch recipient user details');
                    }

                    server.publish(`user-${publicKeyData.data.phoneNumber}`, JSON.stringify({
                        type: 'transaction-notification',
                        data: {
                            senderId: from.publicKey,
                            amount
                        }
                    }));
                    
                    console.log('\n@@@@' + '='.repeat(80) + '\n');
                    return Response.json({ 
                        result 
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
        '/deposit': {
            POST: async req => {
                // Add CORS headers to auth check
                const auth = requirePermission('deposit')(req);
                if (!auth.authenticated) {
                    return Response.json({ 
                        error: auth.error 
                    }, { 
                        status: auth.status,
                        headers: corsHeaders  // Add CORS headers
                    });
                }

                try {
                    const body = await req.json();
                    const to = body["to"];
                    const amount = body["amount"];
                    
                    console.log('Processing deposit:', {
                        to: to.substring(0, 32) + '...',
                        amount
                    });
        
                    const tx = { 
                        from: null, 
                        to: to, 
                        amount: amount, 
                        type: "DEPOSIT" 
                    };
                    const result = await received_transaction(tx);
                    
                    return Response.json({ 
                        success: true,
                        result 
                    }, { 
                        headers: corsHeaders
                    });
                } catch (error) {
                    console.error('Deposit error:', error);
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
        '/withdraw': { 
            POST: async (req) => {
                // Add CORS headers to auth check
                
                const auth = requirePermission('withdraw')(req);
                if (!auth.authenticated) {
                    return Response.json({ 
                        error: auth.error 
                    }, { 
                        status: auth.status,
                        headers: corsHeaders  // Add CORS headers
                    });
                }

                try {
                    const body = await req.json();
                    //console.log(body)
                    const { from, amount } = body;
                    const tx = { from, to: null, amount, type: "WITHDRAW" };
                    const result = await received_transaction(tx);
                    return Response.json({ 
                        result 
                    }, { 
                        headers: corsHeaders  // Add CORS headers
                    });
                } catch (error) {
                    return Response.json({ 
                        error: error.message 
                    }, { 
                        status: 400,
                        headers: corsHeaders  // Add CORS headers
                    });
                }
            }
        },
        '/balance': {
            GET: async (req) => {
                const auth = authenticateToken(req);
                if (!auth.authenticated) {
                    return Response.json({ error: auth.error }, { status: auth.status });
                }
                // ... balance handling
            }
        },
        '/newuser': async (req) => {
            const user = generateKeyPair();
            return Response.json({ user });
        },
        '/admin/users': {
            GET: async (req) => {
                const auth = requirePermission('manage_users')(req);
                if (!auth.authenticated) {
                    return Response.json({ error: auth.error }, { status: auth.status });
                }
                // ... admin functionality
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
    },
    websocket: {
        open(ws) {
          ws.subscribe(`${ws.data.type}-${ws.data.id}`);
          console.log('WebSocket connection opened:', ws.data.type, ws.data.id);
        },
        message(ws, message) {},
        close(ws) {
          ws.unsubscribe(`${ws.data.type}-${ws.data.id}`);
          console.log('WebSocket connection closed:', ws.data.type, ws.data.id);
        },
    },
        // Global fetch handler
    fetch(req, server) {
        const url = new URL(req.url);
        if (url.pathname === "/ws" && req.method === "GET") {
              const clientType = url.searchParams.get("clientType");
              let id = url.searchParams.get("id");
              
              if (!clientType || !id) {
                return new Response("Missing clientType or id", { status: 400 });
              }
      
              // Format phone number consistently
              if (!id.startsWith('+')) {
                id = ('+' + id).split(" ").join("");
              }
      
              console.log(`Upgrading WebSocket connection for ${clientType} with ID: ${id}`);
          
              const success = server.upgrade(req, { 
                data: { 
                  type: clientType,
                  id 
                } 
              });
              
              return success
                ? undefined
                : new Response("WebSocket upgrade error", { status: 400 });
        }
          
        if (req.method === 'OPTIONS') {
              return new Response(null, {
                status: 204,
                headers: corsHeaders
              });
        }
    }
});

// Make authenticated request
// curl -X POST http://localhost:2222/txn \
// -H "Content-Type: application/json" \
// -H "Authorization: Bearer your-jwt-token" \
// -d '{
//     "from": "sender_address",
//     "to": "recipient_address",
//     "amount": 100
// }'

async function received_transaction(tx) {
    console.log('\n@@@@' + '='.repeat(80) + '\n');
    console.log('\x1b[34m%s\x1b[0m', `\n@@@@Executing transaction: ${tx.type}`);
    const ports = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008];
    const randomPort = ports[Math.floor(Math.random() * ports.length)];
    
    let fromKey = null;
    let toKey = null;

    // Handle different transaction types
    switch (tx.type) {
        case 'DEPOSIT':
            fromKey = null;
            toKey = { publicKey: tx.to };
            break;
        case 'WITHDRAW':
            fromKey = tx.from ? { publicKey: tx.from.publicKey, privateKey: tx.from.privateKey } : null;
            toKey = null;
            break;
        case 'CONTRACT_PAYMENT':
            fromKey = {
                publicKey: typeof tx.from === 'object' ? tx.from.publicKey : tx.from,
                privateKey: tx.from.privateKey || tx.privateKey
            };
            toKey = typeof tx.to === 'object' ? tx.to : { publicKey: tx.to };
            break;
        case 'TRANSFER':
            fromKey = tx.from ? {
                publicKey: tx.from.publicKey,
                privateKey: tx.from.privateKey
            } : null;
            toKey = tx.to ? { publicKey: tx.to } : null;
            break;
    }

    const result = await sendTransaction(fromKey, toKey, tx.amount, randomPort, tx.type);
    
    if (result.error) {
        console.log('\x1b[31m%s\x1b[0m', `@@@@Transaction failed: ${result.error}`);
        if (result.balance !== undefined) {
            console.log('\x1b[31m%s\x1b[0m', `@@@@Available balance: ${result.balance}, Attempted: ${result.attempted}`);
            return `Transaction failed: ${result.error}`;
        }
        return result.error;
    } else {
        console.log('\x1b[32m%s\x1b[0m', '@@@@Transaction successful');
        // Run sync after every successful transaction
        await fetch('http://localhost:2224/sync')
            .then(res => res.json())
            .then(() => new Promise(resolve => setTimeout(resolve, 200)));
        return 'Transaction successful';
    }
}


