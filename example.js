import { Node } from "./node.js";
import { Transaction } from "./transaction.js";
import crypto from "crypto";

// Generate test key pairs
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

// Create test accounts
const alice = generateKeyPair();
const bob = generateKeyPair();
const charlie = generateKeyPair();
const dave = generateKeyPair();

process.env.NETWORK_SECRET = 'test-secret-123';

async function displayChainState(nodePort, message) {
    console.log(`\n${message}`);
    const chain = await fetch(`http://localhost:${nodePort}/chain`, {
        headers: { 'x-auth-token': process.env.NETWORK_SECRET }
    }).then(res => res.json());
    
    console.log('Current Blockchain State:');
    chain.forEach((block, index) => {
        console.log(`\nBlock ${index}:`);
        console.log('Transactions:', block.transactions);
        console.log('Hash:', block.hash.substring(0, 10) + '...');
    });
}

async function checkAllBalances(nodePort) {
    console.log('\nCurrent Balances:');
    const accounts = [
        { name: 'Alice', keys: alice },
        { name: 'Bob', keys: bob },
        { name: 'Charlie', keys: charlie },
        { name: 'Dave', keys: dave }
    ];

    for (const account of accounts) {
        const balanceRes = await fetch(
            `http://localhost:${nodePort}/balance?address=${encodeURIComponent(account.keys.publicKey)}`,
            { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
        );
        const balance = await balanceRes.json();
        console.log(`${account.name}: ${balance.balance} tokens`);
    }
}

async function sendTransaction(from, to, amount, nodePort) {
    try {
        // Create and sign transaction
        const transaction = new Transaction(from.publicKey, to.publicKey, amount);
        transaction.signTransaction(from.privateKey);
        
        // Send transaction
        const txResponse = await fetch(`http://localhost:${nodePort}/transaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': process.env.NETWORK_SECRET
            },
            body: JSON.stringify({
                sender: from.publicKey,
                recipient: to.publicKey,
                amount: amount,
                timestamp: transaction.timestamp,
                signature: transaction.signature
            })
        });

        if (!txResponse.ok) {
            const error = await txResponse.json();
            throw new Error(`Transaction failed: ${error.error}`);
        }

        // Wait for mining and synchronization
        await new Promise(resolve => setTimeout(resolve, 2000));

        console.log(`Transaction successful: ${amount} tokens sent from ${from.publicKey.substring(0, 10)}... to ${to.publicKey.substring(0, 10)}...`);
    } catch (error) {
        console.error('Transaction error:', error.message);
        throw error;
    }
}

async function checkNodesHealth(nodes) {
    console.log('\nChecking health of all nodes...');
    for (let i = 0; i < nodes.length; i++) {
        const port = 3001 + i;
        try {
            const health = await fetch(`http://localhost:${port}/health`, {
                headers: { 'x-auth-token': process.env.NETWORK_SECRET }
            }).then(res => res.json());
            
            console.log(`Node ${i + 1} (port ${port}):`);
            console.log(`  Status: ${health.status}`);
            console.log(`  Blocks: ${health.blockHeight} (${health.blockHeight - 1} transactions processed)`);
            console.log(`  Connected Peers: ${health.peersCount}`);
            
            // Check if this node is in sync with others
            if (i > 0) {
                const mainNodeHealth = await fetch(`http://localhost:3001/health`, {
                    headers: { 'x-auth-token': process.env.NETWORK_SECRET }
                }).then(res => res.json());
                
                if (health.blockHeight !== mainNodeHealth.blockHeight) {
                    console.log(`  WARNING: Node is out of sync! Main node height: ${mainNodeHealth.blockHeight}`);
                }
            }
        } catch (error) {
            console.log(`Node ${i + 1} (port ${port}): OFFLINE or ERROR`);
        }
    }
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
    
    // Start main node first
    const mainNode = await new Node(3001, [], { genesisBalances }).initialize();
    console.log('Main node started on port 3001');
    
    // Wait for main node to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Start other nodes
    const otherNodes = await Promise.all([
        new Node(3002, ['localhost:3001'], { genesisBalances }).initialize(),
        new Node(3003, ['localhost:3001'], { genesisBalances }).initialize(),
        new Node(3004, ['localhost:3001'], { genesisBalances }).initialize()
    ]);
    
    const nodes = [mainNode, ...otherNodes];
    
    // Wait for all nodes to connect
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Display initial state
    await displayChainState(3001, 'Initial blockchain state:');
    await checkAllBalances(3001);

    // Series of transactions
    const transactions = [
        { from: alice, to: bob, amount: 100, message: 'Alice sends 100 to Bob' },
        { from: bob, to: charlie, amount: 50, message: 'Bob sends 50 to Charlie' },
        { from: charlie, to: dave, amount: 75, message: 'Charlie sends 75 to Dave' },
        { from: dave, to: alice, amount: 25, message: 'Dave sends 25 to Alice' }
    ];

    // Execute each transaction
    for (const tx of transactions) {
        console.log(`\nExecuting transaction: ${tx.message}`);
        await sendTransaction(tx.from, tx.to, tx.amount, 3001);
        await displayChainState(3001, 'Updated blockchain state:');
        await checkAllBalances(3001);
        
        // Wait a bit between transactions
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    const healthCheckInterval = setInterval(() => checkNodesHealth(nodes), 60000); // Every minute
    await checkNodesHealth(nodes);

    console.log('\nTransaction series complete. Monitoring node health...');
    console.log('Press Ctrl+C to exit.');

    // Handle cleanup on exit
    process.on('SIGINT', () => {
        clearInterval(healthCheckInterval);
        console.log('\nStopping health checks and exiting...');
        process.exit();
    });
}

main().catch(console.error); 