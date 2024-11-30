import { Blockchain } from "./chain.js";
import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { createHash, randomBytes, generateKeyPairSync, createHmac } from 'crypto';

export const NodeType = {
    CONTROLLER: 'controller',
    SME: 'sme',
    VALIDATOR: 'validator'
};

// Generate test key pairs
export function generateKeyPair() {
    return generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

export class Node {
    constructor(options = {}) {
        this.nodeConfig = {
            // Network configuration
            host: options.host || 'localhost',
            port: options.port || 3000,
            protocol: options.protocol || 'http',
            
            // Node identity
            nodeId: randomBytes(32).toString('hex'),
            nodeType: options.nodeType || NodeType.VALIDATOR,
            
            // Network discovery
            seedNodes: options.seedNodes || [],
            discoveryInterval: options.discoveryInterval || 60000,
            
            // Rate limiting
            rateLimits: {
                CONTROLLER: {
                    sync: 500,      // Chain syncs
                    transaction: 200, // Transaction processing
                    balance: 200,    // Balance checks
                    health: 100,     // Health checks
                    other: 100       // Other requests
                },
                DEFAULT: {
                    sync: 50,
                    transaction: 20,
                    balance: 20,
                    health: 10,
                    other: 10
                }
            }
        };
        this.host = this.nodeConfig.host;
        this.port = this.nodeConfig.port;
        this.seedNodes = this.nodeConfig.seedNodes;
        this.peers = new Map();
        this.rateLimit = new Map(); 
        this.nodeId = randomBytes(32).toString('hex');
        this.maxPeers = options.maxPeers || 10;

        this.wallet = options.wallet || generateKeyPair();
        this.transactionFee = options.transactionFee || 0.01;


        this.nodeType = this.nodeConfig.nodeType || NodeType.VALIDATOR; // Default to validator
        this.nodeId = randomBytes(32).toString('hex');
        this.permissions = this.initializePermissions();

        // Set rate limit based on node type
        if (this.nodeType === NodeType.CONTROLLER) {
            this.rateLimitWindow = 60000;  // 1 minute window
            this.maxRequestsPerWindow = 1000;  // Much higher limit for controller
        } else {
            this.rateLimitWindow = 60000;  // 1 minute window
            this.maxRequestsPerWindow = 100;  // Standard limit for other nodes
        }

        // Controller-Node specific properties
        this.tokenMintingEnabled = this.nodeType === NodeType.CONTROLLER;
        this.insurancePool = this.nodeType === NodeType.CONTROLLER ? new Map() : null;
        // Controller-specific security
        this.depositSecret = options.networkSecret || process.env.NETWORK_SECRET;
        this.depositNonce = new Map(); // Track used nonces
        this.depositTimeWindow = 5 * 60 * 1000; // 5 minutes
        
        // Add rate limiting specifically for deposits
        this.depositRateLimit = {
            window: 1000, // 1 second
            maxDeposits: 500,
            deposits: new Map() // Track deposits per address
        };

        // SME-Node specific properties
        this.businessMetrics = this.nodeType === NodeType.SME ? {
            transactionVolume: 0,
            customerCount: new Set(),
            paymentHistory: [],
            lastActivity: Date.now()
        } : null;
        
        // Initialize blockchain with genesis block
        if (options.genesisBalances) {
            // Sort transactions to ensure consistent genesis block across all nodes
            const genesisTransactions = Object.entries(options.genesisBalances)
                .sort(([addr1], [addr2]) => addr1.localeCompare(addr2))
                .map(([address, amount]) => {
                    const tx = new Transaction(null, address, amount);
                    tx.timestamp = 0; // Fixed timestamp for genesis transactions
                    return tx;
                });
            
            this.blockchain = new Blockchain(genesisTransactions);
        } else {
            this.blockchain = new Blockchain();
        }
        
        
        
        
    }

    async initialize() {
        await this.setupServer();
        console.log(`Node ${this.port}: Server started`);
        this.registerWithSeedNodes();

        // Wait a moment before trying to register with seed nodes
        if (this.seedNodes.length > 0) {
            // Wait for seed nodes to be ready
            await new Promise(resolve => setTimeout(resolve, 1000));
            await this.registerWithSeedNodes();
        }

         // Start peer discovery and sync
         setTimeout(() => {
            this.startPeerDiscovery();
            setInterval(() => this.syncWithPeers(), 5000); // Sync every 5 seconds
            
        }, 10000);
        // Start mining interval
        setInterval(() => this.mineIfNeeded(), 10000); // Check every 10 seconds

        return this;
       
    }

    initializePermissions() {
        switch(this.nodeType) {
            case NodeType.CONTROLLER:
                return {
                    canMintTokens: true,
                    canManageLoans: true,
                    canManageInsurance: true,
                    canValidate: true
                };
            case NodeType.SME:
                return {
                    canProcessPayments: true,
                    canRequestLoans: true,
                    canValidate: false
                };
            default:
                return {
                    canValidate: true
                };
        }
    }

    getNodeAddress() {
        return `${this.nodeConfig.protocol}://${this.nodeConfig.host}:${this.nodeConfig.port}`;
    }

    async registerWithSeedNodes() {
        for (const seedNode of this.seedNodes) {
            let attempts = 0;
            const maxAttempts = 3;
            
            while (attempts < maxAttempts) {
                try {
                    console.log(`Node ${this.host}:${this.port}: Attempting to register with seed node ${seedNode} (attempt ${attempts + 1})`);
                    
                    const response = await fetch(`http://${seedNode}/new-peer`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-auth-token': process.env.NETWORK_SECRET
                        },
                        body: JSON.stringify({
                            peerAddress: `${this.host}:${this.port}`
                        })
                    });
    
                    if (response.ok) {
                        console.log(`Node ${this.host}:${this.port}: Successfully registered with seed node ${seedNode}`);
                        // Add the seed node to our peers list
                        this.peers.set(seedNode, true);
                        break; // Success, exit the retry loop
                    } else {
                        throw new Error(`Failed to register with status ${response.status}`);
                    }
                } catch (error) {
                    attempts++;
                    if (attempts === maxAttempts) {
                        console.error(`Node ${this.host}:${this.port}: Failed to register with seed node ${seedNode} after ${maxAttempts} attempts:`, error.message);
                    } else {
                        console.log(`Node ${this.host}:${this.port}: Retrying registration with ${seedNode} in 1 second...`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                }
            }
        }
    }

    async startPeerDiscovery() {
        // Initial connection to seed nodes
        await this.connectToSeedNodes();

        // Start periodic peer discovery
        setInterval(async () => {
            await this.discoverPeers();
        }, 30000); // Every minute

        // Start local network discovery
        this.startLocalDiscovery();
    }

    async connectToSeedNodes() {
        console.log(`Node ${this.host}:${this.port} connecting to seed nodes...`);
        for (const seed of this.seedNodes) {
            try {
                await this.addPeer(seed);
            } catch (error) {
                console.error(`Node ${this.host}:${this.port}: Failed to connect to seed node ${seed}:`, error.message);
            }
        }
    }

    async discoverPeers() {
        //if (this.peers.size >= this.maxPeers) return;

        console.log(`Node ${this.host}:${this.port}: Starting peer discovery...`);
        
        setInterval(async () => {
            for (const seedNode of this.seedNodes) {
                try {
                    const response = await fetch(`http://${seedNode}/peers`, {
                        headers: { 'x-auth-token': process.env.NETWORK_SECRET }
                    });
                    if (!response.ok) continue;
                    
                    const peers = await response.json();
                    if (Array.isArray(peers)) {
                        peers.forEach(peer => {
                            const peerAddress = `${peer.host}:${peer.port}`;
                            if (peerAddress !== `${this.host}:${this.port}`) {
                                this.peers.set(peerAddress, {
                                    host: peer.host,
                                    port: peer.port,
                                    nodeType: peer.nodeType,
                                    lastSeen: Date.now()
                                });
                            }
                        });
                    }
                } catch (error) {
                    console.error(`Node ${this.port}: Failed to discover peers from ${seedNode}:`, error.message);
                }
            }
        }, this.nodeConfig.discoveryInterval);
    }

    async handleGetPeers(req) {
        return new Response(JSON.stringify(
            Array.from(this.peers.values()).map(peer => ({
                host: peer.host,
                port: peer.port,
                nodeType: peer.nodeType
            }))
        ), {
            headers: { "Content-Type": "application/json" }
        });
    }

    updatePeers(newPeers) {
        for (const peer of newPeers) {
            if (peer.address !== this.getNodeAddress()) {
                this.peers.set(peer.nodeId, {
                    address: peer.address,
                    nodeType: peer.nodeType,
                    lastSeen: Date.now()
                });
            }
        }
    }


    startLocalDiscovery() {
        // Instead of UDP broadcast, we'll scan common local ports
        const scanLocalNetwork = async () => {
            // Scan local network on common ports
            const commonPorts = [8333, 8334, 8335, 8336, 8337];
            for (const port of commonPorts) {
                if (port === this.port) continue; // Skip own port
                
                try {
                    const response = await fetch(`http://localhost:${port}/handshake`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-auth-token': process.env.NETWORK_SECRET,
                            'x-node-id': this.nodeId
                        },
                        body: JSON.stringify({
                            nodeId: this.nodeId,
                            port: this.port,
                            version: '1.0'
                        })
                    });

                    if (response.ok) {
                        await this.addPeer(`localhost:${port}`);
                    }
                } catch (error) {
                    // Silently fail as the port might not be in use
                }
            }
        };

        // Scan every 30 seconds
        setInterval(scanLocalNetwork, 30000);
        scanLocalNetwork(); // Initial scan
    }

    async addPeer(peerAddress) {
        // Clean up the peer address
        peerAddress = peerAddress.replace('http://', '');
        
        if (this.peers.has(peerAddress)) return;
        if (peerAddress === `localhost:${this.port}`) return;

        try {
            const response = await fetch(`http://${peerAddress}/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': process.env.NETWORK_SECRET
                },
                body: JSON.stringify({
                    nodeId: this.nodeId,
                    port: this.port
                })
            });

            if (response.ok) {
                this.peers.set(peerAddress, {
                    address: peerAddress,  // Store the full address
                    lastSeen: Date.now(),
                    nodeId: (await response.json()).nodeId
                });
                console.log(`Node ${this.host}:${this.port} added peer: ${peerAddress}`);
                await this.syncWithPeers();
            }
        } catch (error) {
            console.error(`Node ${this.host}:${this.port}: Failed to connect to peer ${peerAddress}:`, error.message);
        }
    }

    // Server Setup
    async setupServer() {
        return new Promise((resolve) => {
            Bun.serve({
                port: this.port,
                fetch: async (req) => {
                    try {
                        await this.checkRateLimit(req);
                        await this.authenticatePeer(req);

                        const url = new URL(req.url);
                        
                        switch(true) {
                            case req.method === "POST" && url.pathname === "/handshake":
                                return await this.handleHandshake(req);
                            case req.method === "POST" && url.pathname === "/transaction":
                                return await this.handleTransaction(req);
                            case req.method === "POST" && url.pathname === "/block":
                                return await this.handleNewBlock(req);
                            case req.method === "POST" && url.pathname === "/new-peer":
                                return await this.handleNewPeer(req);
                            case req.method === "GET" && url.pathname === "/peers":
                                return await this.handleGetPeers(req);
                            case req.method === "GET" && url.pathname === "/health":
                                return await this.handleHealthCheck(req);
                            case req.method === "GET" && url.pathname === "/chain":
                                return await this.handleGetChain(req);
                            case req.method === "GET" && url.pathname === "/balance":
                                return await this.handleGetBalance(req);
                            case req.method === "POST" && url.pathname === "/mine":
                                return await this.handleMine(req);
                            case req.method === "GET" && url.pathname === "/get-key":
                                return await this.handleGetPublicKey(req);
                            default:
                                return new Response(JSON.stringify({ error: "Not Found" }), {
                                    status: 404,
                                    headers: { "Content-Type": "application/json" }
                                });
                        }
                    } catch (error) {
                        return new Response(JSON.stringify({ error: error.message }), {
                            status: error.message.includes('Rate limit') ? 429 : 401,
                            headers: { "Content-Type": "application/json" }
                        });
                    }
                }
            });
            resolve();
    });
    }

    async handleNewPeer(req) {
        try {
            const { peerAddress } = await req.json();
            if (!this.peers.has(peerAddress) && this.peers.size < this.maxPeers) {
                this.peers.set(peerAddress, {
                    address: peerAddress,
                    host: 'localhost', // Or extract from peerAddress
                    port: peerAddress.split(':')[1],
                    lastSeen: Date.now()
                });
                console.log(`Node ${this.host}:${this.port}: Added new peer ${peerAddress}`);
            }
            return new Response(JSON.stringify({ 
                message: "Peer added",
                currentPeers: Array.from(this.peers.keys())
            }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }


    async handleGetBalance(req) {
        try {
            const url = new URL(req.url);
            const address = url.searchParams.get('address');
            const balance = address ? this.blockchain.getBalance(address) : this.blockchain.getBalance(this.wallet.publicKey);
            
            return new Response(JSON.stringify({ balance }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ 
                error: error.message,
                balance: 0 
            }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleMine(req) {
        try {
            const minerAddress = (await req.json())?.minerAddress;
            this.blockchain.minePendingTransactions(minerAddress);
            
            // Broadcast the new block to all peers
            const newBlock = this.blockchain.getLatestBlock();
            await this.broadcastBlock(newBlock);

            return new Response(JSON.stringify({ 
                message: "Block mined and broadcast successfully" 
            }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleHandshake(req) {
        const body = await req.json();
        const nodeId = req.headers.get('x-node-id');

        return new Response(JSON.stringify({
            nodeId: this.nodeId,
            version: '1.0',
            port: this.port
        }), {
            headers: { "Content-Type": "application/json" }
        });
    }

    async handleTransaction(req) {
        try {
            console.log("Received transaction request");
            const data = await req.json();
            //console.log("Parsed request data:", data);

            if (data.transactions && Array.isArray(data.transactions)) {
                // Handle array of transactions
                // Validate all transactions together
                const totalAmount = data.transactions.reduce((sum, tx) => sum + tx.amount, 0);
                
                if (data.transactions[0].sender !== null && data.transactions[0].type !== "DEPOSIT") {
                    const senderBalance = this.blockchain.getBalance(data.transactions[0].sender);
                    if (senderBalance < totalAmount) {
                        throw new Error("Insufficient balance for combined transactions");
                    }
                }

                // Create and validate Transaction objects
                const transactionObjects = data.transactions.map(txData => {
                    const transaction = new Transaction(
                        txData.sender,
                        txData.recipient,
                        txData.amount,
                        txData.timestamp,
                        txData.type
                    );
                    
                    // Copy over additional properties
                    transaction.signature = txData.signature;
                    if (txData.nonce) transaction.nonce = txData.nonce;
                    if (txData.authorization) transaction.authorization = txData.authorization;

                    if (txData.type === "FEE") {
                        transaction.skipSignatureValidation = true; 
                    }
                    
                    console.log("Txn:", transaction);
                    return transaction;
                });


                // Create Transaction objects and add them all
                for (const transaction of transactionObjects) {
                    const txHash = transaction.calculateHash();
                    // Check if transaction is already in pending or in recent blocks
                    if (this.blockchain.pendingTransactions.some(tx => tx.calculateHash() === txHash)) {
                        return new Response(JSON.stringify({ 
                            message: "Transaction already pending" 
                        }), {
                            headers: { "Content-Type": "application/json" }
                        });
                    }

                    // Check last N blocks for this transaction
                    const recentBlocks = this.blockchain.chain.slice(-10); // Last 10 blocks
                    const isProcessed = recentBlocks.some(block => 
                        block.transactions.some(tx => tx.calculateHash() === txHash)
                    );
                    
                    if (isProcessed) {
                        return new Response(JSON.stringify({ 
                            message: "Transaction already processed" 
                        }), {
                            headers: { "Content-Type": "application/json" }
                        });
                    }

                    // For SME nodes, track business metrics
                    if (this.nodeType === NodeType.SME && transaction.type !== "FEE") {
                        this.businessMetrics.transactionVolume += data.amount;
                        this.businessMetrics.lastActivity = Date.now();
                        // Add sender to customer count if not null (not a genesis transaction)
                        if (data.sender) {
                            this.businessMetrics.customerCount.add(data.sender);
                        }
                    }

                   //ADD unique txn 
                    this.blockchain.addTransaction(transaction);
                    
                }
                // Broadcast all transactions
                //await this.broadcastTransaction(transactionObjects);
                // Trigger mining check
                this.mineIfNeeded();  
                return new Response(JSON.stringify({ 
                    message: "Transaction added successfully",
                    status: "accepted",
                    transaction: transactionObjects
                }), {
                    headers: { "Content-Type": "application/json" }
                });

            } else {
                // Transaction hash checking to prevent duplicates
                // Create Transaction object from request data
                const txn = new Transaction(
                    data.sender,
                    data.recipient,
                    data.amount,
                    data.timestamp,
                    data.type
                );
                
                // Copy over any additional properties
                if (data.signature) txn.signature = data.signature;
                if (data.nonce) txn.nonce = data.nonce;
                if (data.authorization) txn.authorization = data.authorization;

                // Now we can use transaction methods
                const txHash = txn.calculateHash();

                // Check if transaction is already in pending or in recent blocks
                if (this.blockchain.pendingTransactions.some(tx => tx.calculateHash() === txHash)) {
                    return new Response(JSON.stringify({ 
                        message: "Transaction already pending" 
                    }), {
                        headers: { "Content-Type": "application/json" }
                    });
                }

                // Check last N blocks for this transaction
                const recentBlocks = this.blockchain.chain.slice(-10); // Last 10 blocks
                const isProcessed = recentBlocks.some(block => 
                    block.transactions.some(tx => tx.calculateHash() === txHash)
                );
                
                if (isProcessed) {
                    return new Response(JSON.stringify({ 
                        message: "Transaction already processed" 
                    }), {
                        headers: { "Content-Type": "application/json" }
                    });
                }

                // Validate transaction type and permissions
                // Special handling for deposits through controller node
                if (data.type === 'DEPOSIT') {
                    // 1. Verify node type
                    if (this.nodeType !== NodeType.CONTROLLER) {
                        return new Response(JSON.stringify({
                            error: 'Unauthorized: Not a controller node'
                        }), { status: 403 });
                    }

                    // 2. Verify deposit authorization
                    if (!this.verifyDepositAuthorization(data)) {
                        return new Response(JSON.stringify({
                            error: 'Invalid deposit authorization'
                        }), { status: 401 });
                    }

                    // 3. Check rate limits
                    if (!this.checkDepositRateLimit(data.recipient, data.amount)) {
                        return new Response(JSON.stringify({
                            error: 'Deposit rate limit exceeded'
                        }), { status: 429 });
                    }

                    // 4. Verify nonce hasn't been used
                    if (this.depositNonce.has(data.nonce)) {
                        return new Response(JSON.stringify({
                            error: 'Duplicate deposit nonce'
                        }), { status: 400 });
                    }

                    // 5. Store nonce with timestamp
                    this.depositNonce.set(data.nonce, Date.now());

                    // Create and process deposit transaction
                    const transaction = new Transaction(null, data.recipient, data.amount);
                    transaction.timestamp = data.timestamp || Date.now();
                    transaction.depositAuth = data.authorization;
                    
                    this.blockchain.addTransaction(transaction);
                    this.mineIfNeeded();

                    // Update rate limiting
                    this.updateDepositRateLimit(data.recipient, data.amount);

                    return new Response(JSON.stringify({ 
                        message: "Deposit processed successfully",
                        status: "accepted",
                        transaction: transaction
                    }));
                }

                // Handle withdrawals
                if (data.type === 'WITHDRAW') {
                    // 1. Verify node type
                    if (this.nodeType !== NodeType.CONTROLLER) {
                        return new Response(JSON.stringify({
                            error: 'Unauthorized: Not a controller node'
                        }), { status: 403 });
                    }

                    // 2. Create transaction object for withdrawal
                    const transaction = new Transaction(
                        data.sender,
                        null,  // Null recipient for withdrawals
                        data.amount
                    );
                    transaction.timestamp = data.timestamp;
                    transaction.signature = data.signature;
                    transaction.type = "WITHDRAW";

                    // 3. Verify withdrawal authorization
                    if (!this.verifyWithdrawalAuthorization(data)) {
                        return new Response(JSON.stringify({
                            error: 'Invalid withdrawal authorization'
                        }), { status: 401 });
                    }

                    // 4. Check balance
                    const senderBalance = this.blockchain.getBalance(data.sender);
                    if (senderBalance < data.amount) {
                        return new Response(JSON.stringify({
                            error: 'Insufficient balance',
                            status: 'rejected',
                            balance: senderBalance,
                            attempted: data.amount
                        }), { status: 400 });
                    }

                    // 5. Add to blockchain's pending transactions
                    this.blockchain.addTransaction(transaction);
                    this.mineIfNeeded();

                    return new Response(JSON.stringify({
                        message: "Withdrawal processed successfully",
                        status: "accepted",
                        transaction: transaction
                    }));
                }

                // For SME nodes, track business metrics
                if (this.nodeType === NodeType.SME) {
                    this.businessMetrics.transactionVolume += data.amount;
                    this.businessMetrics.lastActivity = Date.now();
                    // Add sender to customer count if not null (not a genesis transaction)
                    if (data.sender) {
                        this.businessMetrics.customerCount.add(data.sender);
                    }
                }

                // For validator nodes, perform additional validation
                if (this.nodeType === NodeType.VALIDATOR) {
                    // Add any specific validation logic here
                    const senderBalance = this.blockchain.getBalance(data.sender);
                    if (senderBalance < data.amount) {
                        return new Response(JSON.stringify({
                            error: 'Insufficient funds',
                            balance: senderBalance,
                            attempted: data.amount
                        }), {
                            status: 400,
                            headers: { "Content-Type": "application/json" }
                        });
                    }
                }
                
                // Create new transaction
                const transaction = new Transaction(
                    data.sender,
                    data.recipient,
                    data.amount
                );
                transaction.timestamp = data.timestamp || Date.now();
                transaction.signature = data.signature;
        
                // Validate and add transaction
                try {
                    // Validate transaction
                    if (data.type !== 'DEPOSIT' && !transaction.isValid()) {
                        return new Response(JSON.stringify({ 
                            error: "Invalid transaction signature",
                            status: "rejected"
                        }), {
                            status: 400,
                            headers: { "Content-Type": "application/json" }
                        });
                    }
        
                    // Check balance Node Agnostic
                    const senderBalance = this.blockchain.getBalance(transaction.sender);
                    if (data.type !== 'DEPOSIT' &&senderBalance < transaction.amount + (transaction.amount * this.transactionFee)) {
                        return new Response(JSON.stringify({ 
                            error: "Insufficient balance",
                            status: "rejected",
                            balance: senderBalance,
                            attempted: transaction.amount
                        }), {
                            status: 400,
                            headers: { "Content-Type": "application/json" }
                        });
                    }
        
                    // Add to blockchain's pending transactions
                    this.blockchain.addTransaction(transaction);
                    
                    // Trigger mining check
                    this.mineIfNeeded();
        
                    return new Response(JSON.stringify({ 
                        message: "Transaction added successfully",
                        status: "accepted",
                        transaction: transaction
                    }), {
                        headers: { "Content-Type": "application/json" }
                    });
                } catch (error) {
                    return new Response(JSON.stringify({ 
                        error: error.message,
                        status: "rejected"
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json" }
                    });
                }
            }
        } catch (error) {
            console.error("Error parsing transaction request:", error);
            return new Response(JSON.stringify({ 
                error: "Invalid request format",
                status: "rejected",
                details: error.message
            }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    verifyWithdrawalAuthorization(data) {
        try {
            // 1. Verify timestamp is within acceptable window
            const now = Date.now();
            if (Math.abs(now - data.timestamp) > this.depositTimeWindow) {
                console.log('Withdrawal failed: Timestamp outside window');
                return false;
            }
    
            // 2. Verify nonce hasn't been used (prevent replay attacks)
            if (this.depositNonce.has(data.nonce)) {
                console.log('Withdrawal failed: Nonce already used');
                return false;
            }
    
            // 3. Store nonce
            this.depositNonce.set(data.nonce, Date.now());
    
            // 4. Verify authorization signature
            const message = `${data.sender}:${data.amount}:${data.timestamp}:${data.nonce}`;
            const expectedAuth = createHmac('sha256', process.env.NETWORK_SECRET)  // Use NETWORK_SECRET instead of depositSecret
                .update(message)
                .digest('hex');
    
            const isValid = data.authorization === expectedAuth;
            if (!isValid) {
                console.log('Withdrawal failed: Invalid authorization');
            }
            return isValid;
        } catch (error) {
            console.error('Withdrawal authorization verification failed:', error);
            return false;
        }
    }

    verifyDepositAuthorization(data) {
        try {
            // Verify timestamp is within acceptable window
            const now = Date.now();
            if (Math.abs(now - data.timestamp) > this.depositTimeWindow) {
                return false;
            }

            // Verify authorization signature
            const message = `${data.recipient}:${data.amount}:${data.timestamp}:${data.nonce}`;
            const expectedAuth = createHmac('sha256', this.depositSecret)
                .update(message)
                .digest('hex');

            return data.authorization === expectedAuth;
        } catch (error) {
            console.error('Deposit authorization verification failed:', error);
            return false;
        }
    }

    checkDepositRateLimit(recipient, amount) {
        const now = Date.now();
        const hourDeposits = this.depositRateLimit.deposits.get(recipient) || [];
        
        // Clean up old entries
        const recentDeposits = hourDeposits.filter(
            deposit => now - deposit.timestamp < this.depositRateLimit.window
        );

        // Check number of deposits
        if (recentDeposits.length >= this.depositRateLimit.maxDeposits) {
            return false;
        }

        // Check total amount if needed
        const totalAmount = recentDeposits.reduce((sum, dep) => sum + dep.amount, 0);
        // Add your business logic for maximum deposit amounts here

        return true;
    }

    updateDepositRateLimit(recipient, amount) {
        const now = Date.now();
        const hourDeposits = this.depositRateLimit.deposits.get(recipient) || [];
        
        hourDeposits.push({
            timestamp: now,
            amount: amount
        });

        this.depositRateLimit.deposits.set(recipient, hourDeposits);
    }

    // Periodic cleanup of old nonces and rate limit data
    cleanupDepositData() {
        const now = Date.now();
        
        // Clean up old nonces
        for (const [nonce, timestamp] of this.depositNonce) {
            if (now - timestamp > this.depositTimeWindow) {
                this.depositNonce.delete(nonce);
            }
        }

        // Clean up rate limit data
        for (const [recipient, deposits] of this.depositRateLimit.deposits) {
            const recentDeposits = deposits.filter(
                deposit => now - deposit.timestamp < this.depositRateLimit.window
            );
            if (recentDeposits.length === 0) {
                this.depositRateLimit.deposits.delete(recipient);
            } else {
                this.depositRateLimit.deposits.set(recipient, recentDeposits);
            }
        }
    }


    async handleNewBlock(req) {
        try {
            const blockData = await req.json();
            console.log(`Node ${this.port}: Received new block with hash ${blockData.hash.substring(0, 10)}`);
            console.log('Block data:', blockData);
            
            // Validate block structure first
            if (!blockData || !blockData.hash || !blockData.previousHash || !Array.isArray(blockData.transactions)) {
                throw new Error('Invalid block structure received');
            }
    
            // Reconstruct and validate the block
            const block = this.reconstructBlock(blockData);
            
            // Validate block connects to our chain
            const latestBlock = this.blockchain.getLatestBlock();
            if (block.previousHash !== latestBlock.hash) {
                console.log(`Node ${this.port}: Block doesn't connect. Expected previous hash ${latestBlock.hash.substring(0, 10)}, got ${block.previousHash.substring(0, 10)}`);
                return new Response(JSON.stringify({ 
                    error: "Block doesn't connect to current chain" 
                }), {
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }
    
            // Validate transactions in block
            for (const tx of block.transactions) {
                // Log the transaction being validated
                // console.log('Validating transaction:', {
                //     type: tx.type,
                //     hash: tx.calculateHash().substring(0, 10) + '...',
                //     signature: tx.signature?.substring(0, 10) + '...'
                // });
                // Skip signature validation for FEE transactions
                if (tx.type === "FEE") {
                    // Only validate basic properties for FEE transactions
                    if (!tx.sender || !tx.recipient || !tx.amount) {
                        throw new Error('Invalid FEE transaction structure');
                    }
                    console.log('Skipping validation for FEE transaction');
                    continue; // Skip further validation
                }
                
                // Full validation for non-FEE transactions
                if (tx.type !== "FEE" && !tx.isValid()) {
                    console.error(`Node ${this.host}:${this.port}: Transaction validation failed`, {
                        expectedHash: tx.calculateHash(),
                        type: tx.type,
                        signature: tx.signature,
                        sender: tx.sender?.substring(0, 20) + '...',
                        recipient: tx.recipient?.substring(0, 20) + '...'
                    });
                    throw new Error('Block contains invalid transaction');
                }
            }
    
            // Add block to chain
            this.blockchain.chain.push(block);
            console.log(`Node ${this.port}: Added new block ${block.hash.substring(0, 10)}. Chain height: ${this.blockchain.chain.length}`);
            
            return new Response(JSON.stringify({ 
                message: "Block added successfully",
                height: this.blockchain.chain.length
            }), {
                headers: { "Content-Type": "application/json" }
            });
    
        } catch (error) {
            console.error(`Node ${this.port}: Error handling new block:`, error);
            return new Response(JSON.stringify({ 
                error: error.message 
            }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

 

    // Helper method to reconstruct chain with proper objects
    reconstructChain(chainData) {
        return chainData.map(blockData => {
            const transactions = blockData.transactions.map(txData => {
                const tx = new Transaction(txData.sender, txData.recipient, txData.amount);
                tx.timestamp = txData.timestamp;
                tx.signature = txData.signature;
                return tx;
            });

            const block = new Block(blockData.index, transactions, blockData.previousHash);
            block.timestamp = blockData.timestamp;
            block.nonce = blockData.nonce;
            block.hash = blockData.hash;
            return block;
        });
    }

    reconstructBlock(blockData) {
        try {
            const transactions = blockData.transactions.map(txData => {
                // console.log('Raw transaction data:', {
                //     type: txData.type,
                //     signature: txData.signature?.substring(0, 10) + '...'
                // });
        
                // Create base transaction WITH type
                const tx = new Transaction(
                    txData.sender,
                    txData.recipient,
                    txData.amount,
                    txData.timestamp,
                    txData.type  // Pass the type here!
                );
                
                // Set additional properties
                tx.signature = txData.signature;
                if (txData.type === "FEE") {
                    tx.skipSignatureValidation = true;
                }
        
                // console.log('Reconstructed transaction:', {
                //     type: tx.type,
                //     is_fee: tx.type === "FEE",
                //     skip_validation: tx.skipSignatureValidation,
                //     signature: tx.signature?.substring(0, 10) + '...'
                // });
        
                return tx;
            });
            const block = new Block(
                blockData.index || this.blockchain.chain.length,
                transactions,
                blockData.previousHash
            );
            
            block.hash = blockData.hash;
            block.timestamp = blockData.timestamp;
            block.nonce = blockData.nonce;
            
            return block;
        } catch (error) {
            console.error(`Node ${this.port}: Error reconstructing block:`, error);
            throw new Error('Failed to reconstruct block: ' + error.message);
        }
    }

    
    
    async getChainFromPeer(peerAddress) {
        try {
            const response = await fetch(`http://${peerAddress}/chain`, {
                headers: { 
                    'x-auth-token': process.env.NETWORK_SECRET,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Failed to get chain from peer: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`Node ${this.port}: Failed to get chain from peer ${peerAddress}:`, error.message);
            return null;
        }
    }

    async handleNewPeer(req) {
        try {
            const { peerAddress } = await req.json();
            await this.addPeer(peerAddress);
            
            return new Response(JSON.stringify({ 
                message: "Peer added",
                currentPeers: Array.from(this.peers)
            }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleGetChain(req) {
        try {
            // Convert chain to a serializable format
            const chainData = this.blockchain.chain.map(block => ({
                index: block.index,
                timestamp: block.timestamp,
                transactions: block.transactions.map(tx => ({
                    sender: tx.sender,
                    recipient: tx.recipient,
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    signature: tx.signature
                })),
                previousHash: block.previousHash,
                hash: block.hash,
                nonce: block.nonce
            }));
    
            return new Response(JSON.stringify(chainData), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            console.error('Error getting chain:', error);
            return new Response(JSON.stringify({ error: 'Error retrieving chain' }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // async handleGetPeers(req) {
    //     return new Response(JSON.stringify({
    //         peers: Array.from(this.peers.keys())
    //     }), {
    //         headers: { "Content-Type": "application/json" }
    //     });
    // }

    async handleHealthCheck(req) {
        try {
            const health = {
                status: 'healthy',
                blockHeight: this.blockchain.chain.length,
                peersCount: this.peers.size,
                nodeType: this.nodeType,
                pendingTransactions: this.blockchain.pendingTransactions.length
            };
            
            return new Response(JSON.stringify(health), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            console.error(`Node ${this.port}: Health check failed:`, error);
            return new Response(JSON.stringify({
                status: 'unhealthy',
                error: error.message
            }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleGetPublicKey(req) {
        try {
            return new Response(JSON.stringify({ 
                publicKey: this.wallet.publicKey 
            }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ 
                error: "Error retrieving public key",
                details: error.message 
            }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async broadcastTransaction(transactions) {
        // Normalize input to always be an array
        const txArray = Array.isArray(transactions) ? transactions : [transactions];
        
        const promises = Array.from(this.peers.values()).map(peer => {
            // Get peer address from the peer object/string
            const peerAddress = typeof peer === 'string' ? peer : `${peer.host}:${peer.port}`;
            const [host, port] = peerAddress.split(':');
            const peerUrl = `http://${host}:${port}/transaction`;
            
            console.log("Broadcasting to peer:", peerUrl);
            
            return fetch(peerUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    transactions: txArray 
                })
            }).catch(err => {
                console.warn(`Failed to broadcast to ${peerUrl}:`, err.message);
                return null;
            });
        });
    
        try {
            const results = await Promise.all(promises);
            const successfulBroadcasts = results.filter(r => r !== null);
            console.log(`Successfully broadcast to ${successfulBroadcasts.length}/${promises.length} peers`);
            return successfulBroadcasts;
        } catch (error) {
            console.error("Broadcast error:", error);
            throw new Error("Failed to broadcast transaction");
        }
    }

    async broadcastBlock(block) {
        const promises = Array.from(this.peers.keys()).map(async (peerAddress) => {
            try {
                // Serialize block with its original hash
                const blockData = {
                    index: block.index,
                    timestamp: block.timestamp,
                    transactions: block.transactions.map(tx => ({
                        sender: tx.sender,
                        recipient: tx.recipient,
                        amount: tx.amount,
                        timestamp: tx.timestamp,
                        signature: tx.signature,
                        type: tx.type
                    })),
                    previousHash: block.previousHash,
                    nonce: block.nonce,
                    hash: block.hash // Include original hash
                };
                console.log(`Node ${this.port}: Broadcasting block to peer ${peerAddress}`);
                const response = await fetch(`http://${peerAddress}/block`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-auth-token': process.env.NETWORK_SECRET,
                        'x-forwarded-host': `localhost:${this.port}` // Add sender information
                    },
                    body: JSON.stringify(blockData)
                });
    
                if (!response.ok) {
                    throw new Error(`Failed to broadcast to ${peerAddress}`);
                }
                console.log(`Node ${this.port}: Successfully broadcasted block to ${peerAddress}`);
            } catch (error) {
                console.error(`Node ${this.port}: Failed to broadcast to ${peerAddress}:`, error.message);
            }
        });
    
        await Promise.allSettled(promises);
        console.log(`Node ${this.port}: Broadcasted block to peers`);
    }

    async checkRateLimit(clientId) {
        const now = Date.now();
        if (!this.rateLimit.has(clientId)) {
            this.rateLimit.set(clientId, {
                count: 1,
                windowStart: now
            });
            return true;
        }
    
        const limit = this.rateLimit.get(clientId);
        if (now - limit.windowStart > this.rateLimitWindow) {
            // Reset window
            limit.count = 1;
            limit.windowStart = now;
            return true;
        }
    
        if (limit.count >= this.maxRequestsPerWindow) {
            console.log(`Rate limit exceeded for client ${clientId.substring(0, 8)}...`);
            return false;
        }
    
        limit.count++;
        return true;
    }

    async checkRateLimitX(req) {
        const ip = req.headers.get('x-forwarded-for') || 'localhost';
        const now = Date.now();
        const windowMs = this.rateLimitWindow; // 1 minute
        const maxRequests = this.maxRequestsPerWindow;

        if (!this.rateLimit.has(ip)) {
            this.rateLimit.set(ip, {
                count: 1,
                resetTime: now + windowMs
            });
            return;
        }

        const limit = this.rateLimit.get(ip);
        if (now > limit.resetTime) {
            limit.count = 1;
            limit.resetTime = now + windowMs;
        } else if (limit.count >= maxRequests) {
            throw new Error('Rate limit exceeded');
        } else {
            limit.count++;
        }
    }

    async authenticatePeer(req) {
        const authToken = req.headers.get('x-auth-token');
        if (!authToken) {
            throw new Error('Authentication required');
        }

        // Simple shared secret authentication
        // In production, use a more secure method
        if (authToken !== process.env.NETWORK_SECRET) {
            throw new Error('Invalid authentication');
        }
    }

    async resolveChainConflicts() {
        let maxLength = this.blockchain.chain.length;
        let bestChain = null;
        let consensusReached = false;

        // Get all peer chains
        const peerChains = await Promise.all(
            Array.from(this.peers.keys()).map(async peer => {
                try {
                    const response = await fetch(`http://${peer}/chain`);
                    return await response.json();
                } catch (error) {
                    console.error(`Failed to fetch chain from ${peer}:`, error);
                    return null;
                }
            })
        );

        // Filter out failed responses and count chain occurrences
        const chainOccurrences = new Map();
        peerChains.filter(Boolean).forEach(chain => {
            const chainHash = this.getChainHash(chain);
            chainOccurrences.set(chainHash, (chainOccurrences.get(chainHash) || 0) + 1);

            if (chain.length > maxLength && this.blockchain.isValidChain(chain)) {
                maxLength = chain.length;
                bestChain = chain;
            }
        });

        // Check if we have consensus (more than 51% of peers agree)
        const totalPeers = this.peers.size;
        for (const [chainHash, count] of chainOccurrences) {
            if (count > totalPeers / 2) {
                consensusReached = true;
                break;
            }
        }

        // Update our chain if necessary
        if (consensusReached && bestChain) {
            this.blockchain.chain = bestChain;
            return true;
        }

        return false;
    }

    getChainHash(chain) {
        return createHash('sha256')
            .update(JSON.stringify(chain))
            .digest('hex');
    }




    async broadcastChain() {
        const promises = Array.from(this.peers.values()).map(peer =>
            fetch(`${peer}/chain`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': process.env.NETWORK_SECRET
                },
                body: JSON.stringify(this.blockchain.chain)
            })
        );
        await Promise.all(promises);
    }

    async syncWithPeers() {
        if (this.peers.size === 0) return;
        
        try {
            let longestChain = this.blockchain.chain;
            let maxHeight = longestChain.length;
            let syncedWithPeer = false;
    
            // Get all peer chains
            for (const [peerAddress, peerInfo] of this.peers) {
                if (!peerAddress || peerAddress.includes(undefined)){
                    console.log(`Node ${this.host}:${this.port}: Skipping invalid peer address: ${peerAddress}`);
                    this.peers.delete(peerAddress);
                    continue;
                }
                try {
                    console.log(`Node ${this.host}:${this.port}: Syncing with peer ${peerAddress}`);
                    const response = await fetch(`http://${peerAddress}/chain`, {
                        headers: { 
                            'x-auth-token': process.env.NETWORK_SECRET,
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (!response.ok) {
                        console.log(`Node ${this.host}:${this.port}: Failed to get chain from ${peerAddress}, status: ${response.status}`);
                        continue;
                    }
                    
                    const peerChainData = await response.json();
                    
                    // Skip if peer chain is empty or invalid
                    if (!Array.isArray(peerChainData) || peerChainData.length === 0) {
                        console.log(`Node ${this.host}:${this.port}: Invalid chain data from ${peerAddress}`);
                        continue;
                    }
    
                    // Reconstruct and validate the chain
                    const reconstructedChain = this.reconstructChain(peerChainData);
                    
                    if (reconstructedChain.length > maxHeight && 
                        this.blockchain.isValidChain(reconstructedChain)) {
                        longestChain = reconstructedChain;
                        maxHeight = reconstructedChain.length;
                        syncedWithPeer = true;
                        console.log(`Node ${this.host}:${this.port}: Found longer valid chain from ${peerAddress} (${maxHeight} blocks)`);
                    }
                } catch (error) {
                    console.error(`Node ${this.host}:${this.port}: Failed to sync with peer ${peerAddress}:`, error.message);
                }
            }
    
            // Update chain only if we found a longer valid chain
            if (syncedWithPeer && maxHeight > this.blockchain.chain.length) {
                const oldLength = this.blockchain.chain.length;
                this.blockchain.chain = longestChain;
                console.log(`Node ${this.host}:${this.port}: Updated chain from height ${oldLength} to ${maxHeight}`);
                return true;
            }
            
            console.log(`Node ${this.host}:${this.port}: Already on longest chain (height: ${this.blockchain.chain.length})`);
            return false;
        } catch (error) {
            console.error(`Node ${this.host}:${this.port}: Sync error:`, error.message);
            return false;
        }
    }

   
    async mineIfNeeded() {
        if (this.blockchain.pendingTransactions.length > 0 ) {
            console.log(`Node ${this.host}:${this.port}: Mining block with ${this.blockchain.pendingTransactions.length} transactions`);          
            try {
                const newBlock = this.blockchain.minePendingTransactions(this.wallet.publicKey);
                if (newBlock) {
                    console.log(`Node ${this.host}:${this.port}: Mined new block ${newBlock.hash.substring(0, 10)}`);
                    console.log(`Node ${this.host}:${this.port}: Earned mining reward of ${this.blockchain.miningReward} tokens`);
                    
                    await this.broadcastBlock(newBlock);
                    console.log(`Node ${this.host}:${this.port}: Broadcasted block to peers`);
                }
            } catch (error) {
                console.error(`Node ${this.host}:${this.port}: Mining failed:`, error);
            }
        }
    }

    // Controller-Node specific methods
    async handleMintTokens(req) {
        if (this.nodeType !== NodeType.CONTROLLER) {
            return new Response(JSON.stringify({ error: "Unauthorized: Not a controller node" }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        const { address, amount } = await req.json();
        // Implement minting logic
    }

    async handleLoanRequest(req) {
        if (this.nodeType !== NodeType.CONTROLLER) {
            return new Response(JSON.stringify({ error: "Unauthorized: Not a controller node" }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        const { smeAddress, amount, terms } = await req.json();
        // Implement loan processing logic
    }

    async handleInsurancePool(req) {
        if (this.nodeType !== NodeType.CONTROLLER) {
            return new Response(JSON.stringify({ error: "Unauthorized: Not a controller node" }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        // Implement insurance pool management
    }

    // SME-Node specific methods
    async handleCustomerPayment(req) {
        if (this.nodeType !== NodeType.SME) {
            return new Response(JSON.stringify({ error: "Unauthorized: Not an SME node" }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        const { customerId, amount } = await req.json();
        this.businessMetrics.customerCount.add(customerId);
        this.businessMetrics.transactionVolume += amount;
        this.businessMetrics.paymentHistory.push({
            timestamp: Date.now(),
            amount,
            customerId
        });
        
        // Process payment through blockchain
    }

    async getCreditScore() {
        if (this.nodeType !== NodeType.SME) {
            return new Response(JSON.stringify({ error: "Unauthorized: Not an SME node" }), {
                status: 403,
                headers: { "Content-Type": "application/json" }
            });
        }

        // Calculate credit score based on businessMetrics
        const score = this.calculateCreditScore();
        return new Response(JSON.stringify({ score }), {
            headers: { "Content-Type": "application/json" }
        });
    }


} 