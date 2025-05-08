import { Blockchain } from "./chain.js";
import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { ChainStorage } from './chainStorage.js';
import { createHash, randomBytes, generateKeyPairSync, createHmac } from 'crypto';




const SAVE_INTERVAL = 20000;
const CONTROLLER_PORT = 3001;
process.env.NETWORK_SECRET = 'test-secret-123';

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
    constructor({ host, port, nodeType, seedNodes, genesisBalances, existingChain }) {
        this.nodeConfig = {
            // Network configuration
            host: host || 'localhost',
            port: port || 3000,
            protocol: 'http',
            
            // Node identity
            nodeId: randomBytes(32).toString('hex'),
            nodeType: nodeType || NodeType.VALIDATOR,
            
            // Network discovery
            seedNodes: seedNodes || [],
            discoveryInterval: 60000,
            
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

        this.options = { host, port, nodeType, seedNodes, genesisBalances };

        this.wallet = genesisBalances ? Object.keys(genesisBalances)[0] : generateKeyPair();
        this.transactionFee = 0.01;

        this.nodeType = this.nodeConfig.nodeType || NodeType.VALIDATOR; // Default to validator
        this.nodeId = randomBytes(32).toString('hex');
        this.permissions = this.initializePermissions();
        
        this.peerDiscoveryInterval = 30000;
        this.peerMaintenanceInterval = 60000;

        // Set rate limit based on node type
        if (this.nodeType === NodeType.CONTROLLER) {
            this.rateLimitWindow = 60000;  // 1 minute window
            this.maxRequestsPerWindow = 1000;  // Much higher limit for controller
            this.maxPeers = 100;
            this.minPeers = 3;  //minimum peer requirement
        } else {
            this.rateLimitWindow = 60000;  // 1 minute window
            this.maxRequestsPerWindow = 100;  // Standard limit for other nodes
            this.maxPeers = 20;
            this.minPeers = 3;  //minimum peer requirement
        }

        // Controller-Node specific properties
        this.tokenMintingEnabled = this.nodeType === NodeType.CONTROLLER;
        this.insurancePool = this.nodeType === NodeType.CONTROLLER ? new Map() : null;
        // Controller-specific security
        this.depositSecret = process.env.NETWORK_SECRET;
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

        // Store genesis block hash if loading from existing chain
        if (existingChain && existingChain.chain && existingChain.chain[0]) {
            this.genesisHash = existingChain.chain[0].hash;
        }

        // Initialize blockchain first
        this.blockchain = new Blockchain();  // Create empty blockchain

        if (this.nodeType === NodeType.CONTROLLER) {
            // Controller node initialization will happen in initialize()
        } else {
            // Non-controller nodes start with empty chain and sync later
            console.log(`Node ${this.port}: Initialized with empty chain, waiting for sync`);
        }

        // Set up periodic chain saving for controller node
        if (this.nodeType === NodeType.CONTROLLER) {
            this.chainSaveInterval = setInterval(async () => {
                if (this.blockchain && this.blockchain.chain) {
                    await ChainStorage.saveChain(this.blockchain);
                }
            }, SAVE_INTERVAL);
        }
    }

    async initializeControllerChain(existingChain, genesisBalances) {
        try {
            // Try to load chain from storage first
            const chainData = await ChainStorage.loadChain();
            
            if (chainData && chainData.chain && chainData.chain.length > 0) {
                console.log(`Loading existing chain with ${chainData.chain.length} blocks...`);
                const reconstructedChain = this.reconstructChainFromData(chainData);
                this.blockchain = new Blockchain(undefined, reconstructedChain);
                this.genesisHash = reconstructedChain[0].hash;
                console.log(`📦 Initialized controller node with existing chain (${reconstructedChain.length} blocks)`);
                return;
            }

            // If no valid chain in storage, create new one
            console.log('Creating new genesis block as controller node');
            if (genesisBalances) {
                const genesisTransactions = Object.entries(genesisBalances)
                    .sort(([addr1], [addr2]) => addr1.localeCompare(addr2))
                    .map(([address, amount]) => {
                        const tx = new Transaction(null, address, amount);
                        tx.timestamp = 0; // Consistent timestamp for genesis
                        return tx;
                    });
                this.blockchain = new Blockchain(genesisTransactions);
            } else {
                this.blockchain = new Blockchain();
            }
            this.genesisHash = this.blockchain.chain[0].hash;
            
            // Save the new chain immediately
            await ChainStorage.saveChain(this.blockchain);
        } catch (error) {
            console.error('Failed to initialize controller chain:', error);
            throw error;
        }
    }

    async syncGenesisFromController() {
        console.log(`Node ${this.port}: Attempting to sync full chain from controller`);
        let attempts = 0;
        const maxAttempts = 5;
        
        while (attempts < maxAttempts) {
            try {
                const response = await fetch(`http://localhost:${CONTROLLER_PORT}/chain`, {
                    headers: { 'x-auth-token': process.env.NETWORK_SECRET }
                });
                
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                
                const chainData = await response.json();
                if (!chainData || !Array.isArray(chainData) || chainData.length === 0) {
                    throw new Error('Invalid chain data received');
                }

                console.log(`Node ${this.port}: Received ${chainData.length} blocks from controller`);

                // Reconstruct the chain
                const reconstructedChain = chainData.map((blockData, index) => {
                    try {
                        const transactions = blockData.transactions.map(txData => {
                            const tx = new Transaction(
                                txData.sender,
                                txData.recipient,
                                txData.amount
                            );
                            tx.timestamp = txData.timestamp;
                            tx.type = txData.type || 'TRANSFER';
                            if (txData.signature) tx.signature = txData.signature;
                            if (txData.nonce) tx.nonce = txData.nonce;
                            if (txData.authorization) tx.authorization = txData.authorization;
                            return tx;
                        });

                        const block = new Block(
                            blockData.index,
                            transactions,
                            blockData.previousHash
                        );
                        block.hash = blockData.hash;
                        block.timestamp = blockData.timestamp;
                        block.nonce = blockData.nonce;
                        return block;
                    } catch (error) {
                        console.error(`Error reconstructing block at index ${index}:`, error);
                        return null;
                    }
                }).filter(block => block !== null);

                if (reconstructedChain.length === 0) {
                    throw new Error('Failed to reconstruct any blocks');
                }

                // Initialize blockchain with reconstructed chain
                this.blockchain = new Blockchain(undefined, reconstructedChain);
                this.genesisHash = reconstructedChain[0].hash;
                console.log(`Node ${this.port}: Successfully synced chain with ${reconstructedChain.length} blocks. Genesis: ${this.genesisHash}`);
                return;
            } catch (error) {
                console.error(`Node ${this.port}: Sync attempt ${attempts + 1} failed:`, error);
                attempts++;
                if (attempts < maxAttempts) {
                    await new Promise(resolve => setTimeout(resolve, 1000 * attempts));
                }
            }
        }
        
        throw new Error(`Failed to sync with controller after ${maxAttempts} attempts`);
    }

    async initialSync() {
        try {
            // Sync the entire chain from controller
            await this.syncGenesisFromController();
            
            // No need for additional sync since we already have the full chain
            console.log(`Node ${this.port}: Initial sync complete. Chain height: ${this.blockchain.chain.length}`);
        } catch (error) {
            console.error(`Node ${this.port}: Initial sync failed:`, error);
        }
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
        if (this.peers.size >= this.maxPeers) return;
        
        const discoveredPeers = new Set();
        const maxPeersToAdd = this.maxPeers - this.peers.size;
        
        // First round: Get peers from seed nodes
        for (const seedNode of this.seedNodes) {
            try {
                const peers = await this.getPeersFromNode(seedNode);
                peers.forEach(peer => {
                    const peerAddress = `${peer.host}:${peer.port}`;
                    discoveredPeers.add(peerAddress);
                });
            } catch (error) {
                console.error(`Failed to discover peers from seed ${seedNode}`);
            }
        }
    
        // Second round: Get peers from existing peers
        const existingPeers = Array.from(this.peers.keys());
        for (const peerAddress of existingPeers) {
            try {
                const peers = await this.getPeersFromNode(peerAddress);
                peers.forEach(peer => {
                    const addr = `${peer.host}:${peer.port}`;
                    discoveredPeers.add(addr);
                });
            } catch (error) {
                console.error(`Failed to discover peers from ${peerAddress}`);
            }
        }
    
        // Connect to discovered peers
        let addedPeers = 0;
        for (const peerAddress of discoveredPeers) {
            if (addedPeers >= maxPeersToAdd) break;
            
            // Skip self and existing connections
            if (peerAddress === `${this.host}:${this.port}`) continue;
            if (this.peers.has(peerAddress)) continue;
            
            try {
                await this.addPeer(peerAddress);
                addedPeers++;
                console.log(`Node ${this.port}: Connected to new peer ${peerAddress}`);
            } catch (error) {
                // Silent fail for connection attempts
            }
        }
    }
    
    async getPeersFromNode(nodeAddress) {
        try {
            const response = await fetch(`http://${nodeAddress}/peers`, {
                headers: { 'x-auth-token': process.env.NETWORK_SECRET }
            });
            
            if (!response.ok) return [];
            return await response.json();
        } catch (error) {
            return [];
        }
    }

    async maintainPeerConnections() {
        const minDesiredPeers = Math.min(4, this.maxPeers);  // At least 4 peers if possible
        
        if (this.peers.size < minDesiredPeers) {
            console.log(`Node ${this.port}: Peer count (${this.peers.size}) below minimum, discovering new peers...`);
            await this.discoverPeers();
        }
    
        // Check peer health
        for (const [address, peer] of this.peers.entries()) {
            try {
                const response = await fetch(`http://${address}/health`, {
                    headers: { 'x-auth-token': process.env.NETWORK_SECRET }
                });
                if (!response.ok) {
                    console.log(`Node ${this.port}: Removing unresponsive peer ${address}`);
                    this.peers.delete(address);
                }
            } catch (error) {
                this.peers.delete(address);
            }
        }
    }


    async handleGetPeers(req) {
        // Include our own address in the peer list
        const allPeers = [{
            host: this.host,
            port: this.port,
            nodeType: this.nodeType
        }];
        
        // Add all known peers
        this.peers.forEach((peer, address) => {
            const [host, port] = address.split(':');
            allPeers.push({
                host,
                port: parseInt(port),
                nodeType: peer.nodeType
            });
        });
    
        return new Response(JSON.stringify(allPeers), {
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
        if (peerAddress === `${this.host}:${this.port}`) return;

        try {
            const response = await fetch(`http://${peerAddress}/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': process.env.NETWORK_SECRET
                },
                body: JSON.stringify({
                    nodeId: this.nodeId,
                    host: this.host,
                    port: this.port,
                    nodeType: this.nodeType
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
                    // Handle CORS preflight requests
                    if (req.method === 'OPTIONS') {
                        return new Response(null, {
                            headers: {
                                'Access-Control-Allow-Origin': '*',
                                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token',
                                'Access-Control-Max-Age': '86400'
                            }
                        });
                    }

                    try {
                        await this.checkRateLimit(req);
                        await this.authenticatePeer(req);

                        const url = new URL(req.url);
                        let response;
                        
                        switch(true) {
                            case req.method === "POST" && url.pathname === "/handshake":
                                response = await this.handleHandshake(req);
                                break;
                            case req.method === "POST" && url.pathname === "/transaction":
                                response = await this.handleTransaction(req);
                                break;
                            case req.method === "POST" && url.pathname === "/block":
                                response = await this.handleNewBlock(req);
                                break;
                            case req.method === "POST" && url.pathname === "/new-peer":
                                response = await this.handleNewPeer(req);
                                break;
                            case req.method === "GET" && url.pathname === "/peers":
                                response = await this.handleGetPeers(req);
                                break;
                            case req.method === "GET" && url.pathname === "/health":
                                response = await this.handleHealthCheck(req);
                                break;
                            case req.method === "GET" && url.pathname === "/chain":
                                response = await this.handleGetChain(req);
                                break;
                            case req.method === "GET" && url.pathname === "/balance":
                                response = await this.handleGetBalance(req);
                                break;
                            case req.method === "POST" && url.pathname === "/mine":
                                response = await this.handleMine(req);
                                break;
                            case req.method === "GET" && url.pathname === "/get-key":
                                response = await this.handleGetPublicKey(req);
                                break;
                            default:
                                response = new Response(JSON.stringify({ error: "Not Found" }), {
                                    status: 404,
                                    headers: { "Content-Type": "application/json" }
                                });
                        }

                        // Add CORS headers to all responses
                        const corsHeaders = {
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                            'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token'
                        };

                        // Create new response with CORS headers
                        return new Response(response.body, {
                            status: response.status,
                            headers: {
                                ...Object.fromEntries(response.headers),
                                ...corsHeaders
                            }
                        });

                    } catch (error) {
                        const corsHeaders = {
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                            'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-auth-token'
                        };

                        return new Response(JSON.stringify({ error: error.message }), {
                            status: error.message.includes('Rate limit') ? 429 : 401,
                            headers: { 
                                "Content-Type": "application/json",
                                ...corsHeaders
                            }
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
    
            function normalizeAddress(address) {
                if (!address) return '';
                if (address.includes('-----BEGIN PUBLIC KEY-----')) {
                    return address
                        .replace('-----BEGIN PUBLIC KEY-----', '')
                        .replace('-----END PUBLIC KEY-----', '')
                        .replace(/\n/g, '')
                        .trim();
                }
                return address.trim();
            }
    
            const normalizedAddress = normalizeAddress(address || this.wallet.publicKey);
    
            let balance = 0;
            for (const block of this.blockchain.chain) {
                for (const tx of block.transactions) {
                    // If tx is an array (for bundled/contract transactions)
                    if (Array.isArray(tx)) {
                        for (const subTx of tx) {
                            if (normalizeAddress(subTx.sender) === normalizedAddress) {
                                balance -= Number(subTx.amount);
                            }
                            if (normalizeAddress(subTx.recipient) === normalizedAddress) {
                                balance += Number(subTx.amount);
                            }
                        }
                    } else {
                        if (normalizeAddress(tx.sender) === normalizedAddress) {
                            balance -= Number(tx.amount);
                        }
                        if (normalizeAddress(tx.recipient) === normalizedAddress) {
                            balance += Number(tx.amount);
                        }
                    }
                }
            }
    
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
    


    async handleGetBalanceX(req) {
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
                    const targetPort = 3001;
                    const balanceRes = await fetch(
                        `http://localhost:${targetPort}/balance?address=${encodeURIComponent(data.transactions[0].sender)}`,
                        { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
                    );
                    const { senderBalance } = await balanceRes.json();
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
                    
                    //console.log("Txn:", transaction);
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
            //console.log('Block data:', blockData);
            
            // Validate block structure first
            if (!blockData || !blockData.hash || !blockData.previousHash || !Array.isArray(blockData.transactions)) {
                throw new Error('Invalid block structure received');
            }
    
            // Reconstruct and validate the block
            const block = this.reconstructBlock(blockData);

            // If we're far behind, trigger a full sync instead of processing individual blocks
            if (block.index > this.blockchain.chain.length + 1) {
                console.log(`Node ${this.port}: Received block ${block.index} but current height is ${this.blockchain.chain.length}, triggering sync`);
                await this.syncWithPeers();
                return;
            }
            
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
                    // Verify it's a proper Transaction instance
                    if (!(tx instanceof Transaction) || !tx.sender || !tx.recipient || !tx.amount) {
                        throw new Error('Invalid FEE transaction structure');    
                    }
                    continue;
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
            // First reconstruct all transactions
            const transactions = blockData.transactions.map(txData => {
                const tx = new Transaction(
                    txData.sender,
                    txData.recipient,
                    txData.amount,
                    txData.timestamp,
                    txData.type
                );
                tx.signature = txData.signature;
                if (txData.type === "FEE") {
                    tx.skipSignatureValidation = true;
                }
                return tx;
            });

            // Create new block with EXACT same properties as original
            const block = new Block(
                blockData.index,
                transactions,
                blockData.previousHash
            );
            
            // Important: Copy ALL block properties
            block.timestamp = blockData.timestamp;
            block.nonce = blockData.nonce;
            block.hash = blockData.hash;
            block.index = blockData.index;  // Ensure index is preserved
            
            return block;
        });
    }

    reconstructBlock(blockData) {
        try {
            const transactions = blockData.transactions.map(txData => {
                const tx = new Transaction(
                    txData.sender,
                    txData.recipient,
                    txData.amount,
                    txData.timestamp,
                    txData.type
                );
                // Copy ALL transaction properties
                tx.signature = txData.signature;
                tx.hash = txData.hash;
                tx.nonce = txData.nonce;
                
                // Special handling for FEE transactions
                if (txData.type === "FEE") {
                    tx.skipSignatureValidation = true;
                    tx.signature = "NETWORK_SIGNATURE"; // Preserve network signature
                }
                
                // Handle authorization for special transaction types
                if (txData.type === "DEPOSIT" || txData.type === "WITHDRAW") {
                    tx.authorization = txData.authorization;
                }
                
                return tx;
            });

            const block = new Block(
                blockData.index,
                transactions,
                blockData.previousHash
            );
            
            // Copy ALL block properties
            block.timestamp = blockData.timestamp;
            block.nonce = blockData.nonce;
            block.hash = blockData.hash;
            block.index = blockData.index;
            
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
            
            const chainData = await response.json();
            if (!Array.isArray(chainData)) {
                throw new Error('Invalid chain data format');
            }
            return chainData;  // Return the chain array directly
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
            const authToken = req.headers.get('x-auth-token');
            if (authToken !== process.env.NETWORK_SECRET) {
                return new Response(JSON.stringify({ 
                    error: 'Unauthorized' 
                }), {
                    status: 401,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // Log the chain length being sent
            console.log(`Node ${this.port}: Sending chain with ${this.blockchain.chain.length} blocks`);

            // Ensure we send complete block data
            const chainData = this.blockchain.chain.map(block => ({
                index: block.index,
                timestamp: block.timestamp,
                transactions: block.transactions.map(tx => ({
                    sender: tx.sender,
                    recipient: tx.recipient,
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    signature: tx.signature,
                    type: tx.type || 'TRANSFER',
                    nonce: tx.nonce,
                    authorization: tx.authorization
                })),
                previousHash: block.previousHash,
                hash: block.hash,
                nonce: block.nonce
            }));

            return new Response(JSON.stringify(chainData), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            console.error('Error handling chain request:', error);
            return new Response(JSON.stringify({ 
                error: error.message 
            }), {
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

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
            for (const [peerAddress] of this.peers) {
                if (!peerAddress || peerAddress.includes(undefined)) {
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
                    const reconstructedChain = peerChainData.map(blockData => this.reconstructBlock(blockData));
                    
                    // Verify genesis block matches
                    if (this.genesisHash && reconstructedChain[0]?.hash !== this.genesisHash) {
                        console.log(`Node ${this.host}:${this.port}: Genesis block mismatch with peer ${peerAddress}`);
                        continue;
                    }

                    // Validate the chain and check if it's longer
                    if (reconstructedChain.length > maxHeight && 
                        this.blockchain.isValidChain(reconstructedChain)) {
                        longestChain = reconstructedChain;
                        maxHeight = reconstructedChain.length;
                        syncedWithPeer = true;
                        console.log(`Node ${this.port}: Found longer valid chain (${maxHeight} blocks) from peer ${peerAddress}`);
                    }
                } catch (error) {
                    console.error(`Node ${this.host}:${this.port}: Failed to sync with peer ${peerAddress}:`, error.message);
                }
            }
    
            // Update to the longest valid chain if found
            if (syncedWithPeer && maxHeight > this.blockchain.chain.length) {
                this.blockchain.chain = longestChain;
                console.log(`Node ${this.host}:${this.port}: Updated to longer chain. New height: ${this.blockchain.chain.length}`);
            }
        } catch (error) {
            console.error(`Node ${this.host}:${this.port}: Sync error:`, error.message);
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

    validateChain(chain) {
        try {
            if (!Array.isArray(chain)) return false;
            
            // Validate genesis block consistency if we have a stored genesis hash
            if (this.genesisHash && chain[0]?.hash !== this.genesisHash) {
                console.error('Genesis block mismatch:', {
                    received: chain[0]?.hash?.substring(0, 10),
                    expected: this.genesisHash?.substring(0, 10)
                });
                return false;
            }
            
            // Check each block
            for (let i = 1; i < chain.length; i++) {
                const currentBlock = chain[i];
                const previousBlock = chain[i - 1];
                
                if (!this.isValidBlock(currentBlock, previousBlock)) {
                    return false;
                }
            }
            return true;
        } catch (error) {
            console.error('Chain validation error:', error);
            return false;
        }
    }

    isValidBlock(block, previousBlock) {
        return (
            block &&
            block.hash &&
            block.previousHash &&
            Array.isArray(block.transactions) &&
            block.previousHash === previousBlock.hash &&
            block.index === previousBlock.index + 1
        );
    }

    // Add cleanup method
    cleanup() {
        if (this.chainSaveInterval) {
            clearInterval(this.chainSaveInterval);
            // Save one last time
            if (this.blockchain && this.blockchain.chain) {
                ChainStorage.saveChain(this.blockchain);
            }
        }
    }

    // Helper method to initialize with genesis balances
    initializeWithGenesisBalances(genesisBalances) {
        if (this.nodeType !== NodeType.CONTROLLER) {
            throw new Error('Only controller node can initialize genesis balances');
        }

        if (genesisBalances) {
            const genesisTransactions = Object.entries(genesisBalances)
                .sort(([addr1], [addr2]) => addr1.localeCompare(addr2))
                .map(([address, amount]) => {
                    const tx = new Transaction(null, address, amount);
                    tx.timestamp = 0; // Consistent timestamp for genesis
                    return tx;
                });
            this.blockchain = new Blockchain(genesisTransactions);
        } else {
            this.blockchain = new Blockchain();
        }
        this.genesisHash = this.blockchain.chain[0].hash;
        console.log(`Controller node initialized with genesis block ${this.genesisHash.substring(0, 10)}`);
    }

    // Helper method to reconstruct chain from data
    reconstructChainFromData(chainData) {
        if (!chainData || !chainData.chain || !Array.isArray(chainData.chain)) {
            console.error('Invalid chain data structure:', chainData);
            return [];
        }

        console.log(`Reconstructing chain from data with ${chainData.chain.length} blocks`);
        const reconstructedChain = chainData.chain.map((blockData, index) => {
            if (!blockData) {
                console.error(`Invalid block data at index ${index}`);
                return null;
            }

            try {
                const transactions = blockData.transactions.map(txData => {
                    const tx = new Transaction(
                        txData.sender,
                        txData.recipient,
                        txData.amount
                    );
                    tx.timestamp = txData.timestamp;
                    tx.type = txData.type || 'TRANSFER';
                    if (txData.signature) tx.signature = txData.signature;
                    if (txData.nonce) tx.nonce = txData.nonce;
                    if (txData.authorization) tx.authorization = txData.authorization;
                    return tx;
                });

                const block = new Block(
                    blockData.index,
                    transactions,
                    blockData.previousHash
                );
                block.hash = blockData.hash;
                block.timestamp = blockData.timestamp;
                block.nonce = blockData.nonce;
                return block;
            } catch (error) {
                console.error(`Error reconstructing block at index ${index}:`, error);
                return null;
            }
        }).filter(block => block !== null);

        console.log(`Successfully reconstructed ${reconstructedChain.length} blocks`);
        return reconstructedChain;
    }

    createFeeTransaction(amount) {
        const tx = new Transaction(
            "NETWORK",
            this.publicKey,
            amount,
            Date.now(),
            "FEE"
        );
        // No need to sign FEE transactions
        tx.signature = "NETWORK_SIGNATURE";
        return tx;
    }

    async initialize() {
        try {
            // If controller node, initialize chain first
            if (this.nodeType === NodeType.CONTROLLER) {
                await this.initializeControllerChain(this.options.existingChain, this.options.genesisBalances);
            }

            // Set up server
            await this.setupServer();
            console.log(`Node ${this.port}: Server started`);

            // For non-controller nodes, sync with controller
            if (this.nodeType !== NodeType.CONTROLLER) {
                await this.syncGenesisFromController();
            }

            // Start peer discovery and sync
            setTimeout(() => {
                this.startPeerDiscovery();
                setInterval(() => this.syncWithPeers(), 5000);
            }, 10000);

            setInterval(() => this.discoverPeers(), 30000);
            setInterval(() => this.maintainPeerConnections(), 60000);
            setInterval(() => this.mineIfNeeded(), 10000);

            return this;
        } catch (error) {
            console.error(`Node ${this.port}: Initialization failed:`, error);
            throw error;
        }
    }
} 