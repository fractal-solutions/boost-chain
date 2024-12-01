import { Node, NodeType, generateKeyPair } from "./node.js";
import { Transaction } from "./transaction.js";
import { createHmac, randomBytes } from "crypto";



// Create test accounts
const alice = generateKeyPair();
const bob = generateKeyPair();
const charlie = generateKeyPair();
const dave = generateKeyPair();

process.env.NETWORK_SECRET = 'test-secret-123';

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
        }
    } catch (error) {
        console.error('Error displaying chain state:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
        });
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
        const targetPort = type === "DEPOSIT" || type === "WITHDRAW" ? 3001 : nodePort;
        
        if (type === "DEPOSIT") {
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
            // For non-DEPOSIT/WITHDRAW transactions, check if sender has enough balance for both amount and fee
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
            body: JSON.stringify(txData)
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
    // Initial balances
    const genesisBalances = {
        [alice.publicKey]: 1000,    // Alice starts with 1000
        [bob.publicKey]: 500,       // Bob starts with 500
        [charlie.publicKey]: 750,    // Charlie starts with 750
        [dave.publicKey]: 250        // Dave starts with 250
    };

    // Start nodes sequentially
    console.log('Starting nodes...');
    

    // Start controller node first
    const controllerNode = await new Node({
        host: 'localhost',
        port: 3001,
        nodeType: NodeType.CONTROLLER,
        seedNodes: [],
        genesisBalances
    }).initialize();
    console.log('Controller node started on port 3001');
    
    
    // Wait for main node to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));
 
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
            seedNodes: ['localhost:3001'],
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
            seedNodes: ['localhost:3001'],
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
            seedNodes: ['localhost:3001'],
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
            seedNodes: ['localhost:3001'],
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
            seedNodes: ['localhost:3001'],
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

    
    const nodes = [controllerNode, ...smeNodes, validatorNode];
    
    // Wait for all nodes to connect
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Display initial state
    await displayChainState(3001, 'Initial blockchain state:');
    await checkAllBalances(3001);

    // Series of transactions
    const transactions = [
        { from: null, to: alice, amount: 1000, message: 'Controller node deposits 1000 to Alice', type: "DEPOSIT" },
        { from: alice, to: null, amount: 100, message: 'Alice withdraws 100', type: "WITHDRAW" },
        { from: alice, to: bob, amount: 100, message: 'Alice sends 100 to Bob', type: "TRANSACTION" },
        { from: bob, to: charlie, amount: 50, message: 'Bob sends 50 to Charlie', type: "TRANSACTION" },
        { from: charlie, to: dave, amount: 75, message: 'Charlie sends 75 to Dave', type: "TRANSACTION" },
        { from: dave, to: alice, amount: 25, message: 'Dave sends 25 to Alice', type: "TRANSACTION" },
        { from: alice, to: charlie, amount: 200, message: 'Alice sends 200 to Charlie', type: "TRANSACTION" },
        { from: bob, to: dave, amount: 150, message: 'Bob sends 150 to Dave', type: "TRANSACTION" },
        { from: charlie, to: alice, amount: 100, message: 'Charlie sends 100 to Alice', type: "TRANSACTION" },
        // { from: dave, to: bob, amount: 75, message: 'Dave sends 75 to Bob', type: "TRANSACTION"  },
        // { from: alice, to: dave, amount: 5000, message: 'Alice attempts to send more than she has', type: "TRANSACTION" },
        // { from: bob, to: alice, amount: 12500, message: 'Bob sends 12500 to Alice', type: "TRANSACTION" },
        // { from: charlie, to: bob, amount: 175, message: 'Charlie sends 175 to Bob', type: "TRANSACTION" },
        // { from: dave, to: charlie, amount: 100, message: 'Dave sends 100 to Charlie', type: "TRANSACTION" },
        // { from: alice, to: charlie, amount: 150, message: 'Alice sends 150 to Charlie', type: "TRANSACTION" },
        // { from: bob, to: dave, amount: 200, message: 'Bob sends 200 to Dave', type: "TRANSACTION" }
    ];

    let count = 0;
    while (true) {
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
    process.on('SIGINT', () => {
        clearInterval(healthCheckInterval);
        console.log('\nStopping health checks and exiting...');
        process.exit();
    });
}

main().catch(console.error); 