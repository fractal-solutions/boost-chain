import { Node, NodeType } from "./node.js";
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
    try {
        const response = await fetch(`http://localhost:${nodePort}/chain`, {
            headers: { 'x-auth-token': process.env.NETWORK_SECRET }
        });
        
        const chain = await response.json();
        console.log('Received chain type:', typeof chain);
        console.log('Is array?', Array.isArray(chain));
        //console.log('Chain structure:', JSON.stringify(chain, null, 2));
        
        if (!Array.isArray(chain)) {
            console.error('Chain is not an array. Converting...');
            const chainArray = Object.values(chain);
            if (!Array.isArray(chainArray)) {
                throw new Error('Unable to convert chain to array');
            }
            
            chainArray.forEach((block, index) => {
                console.log(`\nBlock ${index}:`);
                console.log('Transactions:', block.transactions);
                console.log('Hash:', block.hash.substring(0, 10) + '...');
            });
        } else {
            chain.forEach((block, index) => {
                console.log(`\nBlock ${index}:`);
                console.log('Transactions:', block.transactions);
                console.log('Hash:', block.hash.substring(0, 10) + '...');
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

        const result = await txResponse.json();

        if (!txResponse.ok) {
            const error = await txResponse.json();
            throw new Error(`Transaction failed: ${error.error}`);
        }

        // Wait for mining and synchronization
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Format the addresses for readable output
        const formattedFrom = formatAddress(from.publicKey);
        const formattedTo = formatAddress(to.publicKey);

        console.log(`Transaction successful: ${amount} tokens sent from ${formattedFrom} to ${formattedTo}`);
        return result;
    } catch (error) {
        console.error('Transaction error:', error.message);
        return { error: error.message };
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
    const controllerNode = await new Node(3001, [], {
        nodeType: NodeType.CONTROLLER,
        genesisBalances
    }).initialize();
    console.log('Controller node started on port 3001');
    // // Start main node first
    // const mainNode = await new Node(3001, [], { genesisBalances }).initialize();
    // console.log('Main node started on port 3001');
    
    
    // Wait for main node to be ready
    await new Promise(resolve => setTimeout(resolve, 1000));
 
    // Start SME nodes
    const smeNodes = await Promise.all([
        new Node(3002, ['localhost:3001'], {
            nodeType: NodeType.SME,
            genesisBalances,
            businessInfo: {
                    name: "SME_1",
                    industry: "Retail",
                    established: "2020"
            }
        }).initialize(),
        new Node(3003, ['localhost:3001'], {
            nodeType: NodeType.SME,
            genesisBalances,
            businessInfo: {
                name: "SME_2",
                    industry: "Services",
                    established: "2019"
            }
        }).initialize()
    ]);

    // Start validator node
    const validatorNode = await new Node(3004, ['localhost:3001'], {
        nodeType: NodeType.VALIDATOR,
        genesisBalances
    }).initialize();
    // Start other nodes
    // const otherNodes = await Promise.all([
    //     new Node(3002, ['localhost:3001'], { genesisBalances }).initialize(),
    //     new Node(3003, ['localhost:3001'], { genesisBalances }).initialize(),
    //     new Node(3004, ['localhost:3001'], { genesisBalances }).initialize()
    // ]);
    
    const nodes = [controllerNode, ...smeNodes, validatorNode];
    
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
        { from: dave, to: alice, amount: 25, message: 'Dave sends 25 to Alice' },
        { from: alice, to: charlie, amount: 200, message: 'Alice sends 200 to Charlie' },
        { from: bob, to: dave, amount: 150, message: 'Bob sends 150 to Dave' },
        { from: charlie, to: alice, amount: 100, message: 'Charlie sends 100 to Alice' },
        { from: dave, to: bob, amount: 75, message: 'Dave sends 75 to Bob' },
        { from: alice, to: dave, amount: 5000, message: 'Alice attempts to send more than she has' },
        { from: bob, to: alice, amount: 12500, message: 'Bob sends 12500 to Alice' },
        { from: charlie, to: bob, amount: 175, message: 'Charlie sends 175 to Bob' },
        { from: dave, to: charlie, amount: 100, message: 'Dave sends 100 to Charlie' },
        { from: alice, to: charlie, amount: 150, message: 'Alice sends 150 to Charlie' },
        { from: bob, to: dave, amount: 200, message: 'Bob sends 200 to Dave' }
    ];

// Execute each transaction
for (const tx of transactions) {
    console.log(`\nExecuting transaction: ${tx.message}`);
    const ports = [3001, 3002, 3003, 3004];
    const randomPort = ports[Math.floor(Math.random() * ports.length)];
    const result = await sendTransaction(tx.from, tx.to, tx.amount, randomPort);
    
    if (result.error) {
        console.log(`Transaction failed: ${result.error}`);
        if (result.balance !== undefined) {
            console.log(`Available balance: ${result.balance}, Attempted: ${result.attempted}`);
        }
    } else {
        console.log('Transaction successful');
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000));
        await displayChainState(3001, 'Updated blockchain state:');
    await new Promise(resolve => setTimeout(resolve, 2000));
        await checkAllBalances(3001);
    
    // Wait a bit between transactions regardless of success/failure
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