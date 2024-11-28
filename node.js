import { Blockchain } from "./chain.js";
import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { createHash, randomBytes } from 'crypto';

export const NodeType = {
    CONTROLLER: 'controller',
    SME: 'sme',
    VALIDATOR: 'validator'
};

export class Node {
    constructor(port, seedNodes = [], options = {}) {
        this.port = port;
        this.seedNodes = seedNodes;
        this.peers = new Map();
        this.rateLimit = new Map(); 
        this.nodeId = randomBytes(32).toString('hex');
        this.maxPeers = options.maxPeers || 10;

        // Increase rate limit window and max requests
        this.rateLimitWindow = 60000; // 1 minute window
        this.maxRequestsPerWindow = 100; // Allow more requests per window

        this.nodeType = options.nodeType || NodeType.VALIDATOR; // Default to validator
        this.nodeId = randomBytes(32).toString('hex');
        this.permissions = this.initializePermissions();

        // Controller-Node specific properties
        this.tokenMintingEnabled = this.nodeType === NodeType.CONTROLLER;
        this.insurancePool = this.nodeType === NodeType.CONTROLLER ? new Map() : null;

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

    async registerWithSeedNodes() {
        for (const seedNode of this.seedNodes) {
            let attempts = 0;
            const maxAttempts = 3;
            
            while (attempts < maxAttempts) {
                try {
                    console.log(`Node ${this.port}: Attempting to register with seed node ${seedNode} (attempt ${attempts + 1})`);
                    
                    const response = await fetch(`http://${seedNode}/new-peer`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-auth-token': process.env.NETWORK_SECRET
                        },
                        body: JSON.stringify({
                            peerAddress: `localhost:${this.port}`
                        })
                    });
    
                    if (response.ok) {
                        console.log(`Node ${this.port}: Successfully registered with seed node ${seedNode}`);
                        // Add the seed node to our peers list
                        this.peers.set(seedNode, true);
                        break; // Success, exit the retry loop
                    } else {
                        throw new Error(`Failed to register with status ${response.status}`);
                    }
                } catch (error) {
                    attempts++;
                    if (attempts === maxAttempts) {
                        console.error(`Node ${this.port}: Failed to register with seed node ${seedNode} after ${maxAttempts} attempts:`, error.message);
                    } else {
                        console.log(`Node ${this.port}: Retrying registration with ${seedNode} in 1 second...`);
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
        console.log(`Node ${this.port} connecting to seed nodes...`);
        for (const seed of this.seedNodes) {
            try {
                await this.addPeer(seed);
            } catch (error) {
                console.error(`Failed to connect to seed node ${seed}:`, error.message);
            }
        }
    }

    async discoverPeers() {
        if (this.peers.size >= this.maxPeers) return;

        console.log('Starting peer discovery...');
        
        // Ask existing peers for their peer lists
        for (const [peerAddress] of this.peers) {
            try {
                const response = await fetch(`http://${peerAddress}/peers`, {
                    headers: {
                        'x-auth-token': process.env.NETWORK_SECRET,
                        'x-node-id': this.nodeId
                    }
                });
                
                if (!response.ok) continue;
                
                const { peers } = await response.json();
                
                for (const newPeer of peers) {
                    if (this.peers.size >= this.maxPeers) break;
                    if (newPeer === `localhost:${this.port}`) continue; // Skip self
                    if (this.peers.has(newPeer)) continue; // Skip existing peers
                    
                    await this.addPeer(newPeer);
                }
            } catch (error) {
                console.error(`Failed to discover peers from ${peerAddress}:`, error);
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
                    lastSeen: Date.now(),
                    nodeId: (await response.json()).nodeId
                });
                console.log(`Node ${this.port} added peer: ${peerAddress}`);
                await this.syncWithPeers();
            }
        } catch (error) {
            console.error(`Failed to connect to peer ${peerAddress}:`, error.message);
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
                this.peers.set(peerAddress, true);
                console.log(`Node ${this.port}: Added new peer ${peerAddress}`);
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
        const url = new URL(req.url);
        const address = url.searchParams.get('address');
        
        if (!address) {
            return new Response(JSON.stringify({ error: 'Address parameter required' }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }

        try {
            // Use blockchain's getBalance directly
            const balance = this.blockchain.getBalance(address);
            return new Response(JSON.stringify({ balance }), {
                headers: { "Content-Type": "application/json" }
            });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), {
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
            const data = await req.json();
            
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
                if (!transaction.isValid()) {
                    return new Response(JSON.stringify({ 
                        error: "Invalid transaction signature",
                        status: "rejected"
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json" }
                    });
                }
    
                // Check balance
                const senderBalance = this.blockchain.getBalance(transaction.sender);
                if (senderBalance < transaction.amount) {
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
        } catch (error) {
            return new Response(JSON.stringify({ 
                error: "Invalid request format",
                status: "rejected"
            }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleBlock(req) {
        try {
            const blockData = await req.json();
            console.log(`Node ${this.port}: Received new block with hash ${blockData.hash.substring(0, 10)}`);
            
            // First, ensure we're in sync
            const latestBlock = this.blockchain.getLatestBlock();
            if (blockData.previousHash !== latestBlock.hash) {
                console.log(`Node ${this.port}: Block doesn't connect to our chain. Our latest hash: ${latestBlock.hash.substring(0, 10)}`);
                
                // Get the full chain from the peer that sent this block
                const peerAddress = req.headers.get('x-forwarded-host') || 'localhost:3001';
                console.log(`Node ${this.port}: Requesting chain from ${peerAddress}`);
                
                const success = await this.syncWithPeer(peerAddress);
                if (!success) {
                    throw new Error("Failed to sync with peer");
                }
                console.log(`Node ${this.port}: Chain synchronized successfully`);
            }
    
            // Now try to add the block again
            const newBlock = this.reconstructBlock(blockData);
            
            if (this.blockchain.isValidBlock(newBlock)) {
                this.blockchain.chain.push(newBlock);
                console.log(`Node ${this.port}: Added new block ${newBlock.hash.substring(0, 10)}. Chain height: ${this.blockchain.chain.length}`);
                return new Response(JSON.stringify({ message: "Block added successfully" }));
            } else {
                throw new Error("Invalid block after sync");
            }
        } catch (error) {
            console.error(`Node ${this.port}: Error handling block:`, error);
            return new Response(JSON.stringify({ error: error.message }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    async handleNewBlock(request) {
        try {
            const newBlock = await request.json();
            console.log(`Node ${this.port}: Received new block with hash ${newBlock.hash}`);
            
            // Add check for block height
            if (newBlock.index !== this.blockchain.chain.length) {
                console.log(`Node ${this.port}: Block height mismatch. Expected ${this.blockchain.chain.length}, got ${newBlock.index}`);
                await this.syncWithPeer(request.headers.get('x-forwarded-host') || 'localhost:3001');
            }
    
            // Add additional validation
            const latestBlock = this.blockchain.getLatestBlock();
            if (newBlock.previousHash !== latestBlock.hash) {
                console.log(`Node ${this.port}: Block doesn't connect. Expected previous hash ${latestBlock.hash}, got ${newBlock.previousHash}`);
                await this.syncWithPeer(request.headers.get('x-forwarded-host') || 'localhost:3001');
                // Try adding the block again after sync
                if (this.blockchain.isValidBlock(newBlock)) {
                    this.blockchain.chain.push(newBlock);
                    console.log(`Node ${this.port}: Added new block ${newBlock.hash.substring(0, 10)} after sync. Chain height: ${this.blockchain.chain.length}`);
                    return new Response(JSON.stringify({ message: "Block added successfully" }));
                }
            }
    
            if (this.blockchain.isValidBlock(newBlock)) {
                this.blockchain.chain.push(newBlock);
                console.log(`Node ${this.port}: Added new block ${newBlock.hash.substring(0, 10)}. Chain height: ${this.blockchain.chain.length}`);
                return new Response(JSON.stringify({ message: "Block added successfully" }));
            } else {
                //throw new Error("Invalid block after sync");
                return new Response(JSON.stringify({ error: "Invalid block after sync" }), { status: 400 });
            }
        } catch (error) {
            console.error(`Node ${this.port}: Error handling block:`, error);
            return new Response(JSON.stringify({ error: error.message }), { status: 400 });
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
            // Reconstruct transactions exactly as they were
            const transactions = blockData.transactions.map(txData => {
                const tx = new Transaction(txData.sender, txData.recipient, txData.amount);
                tx.timestamp = txData.timestamp; // Use original timestamp
                tx.signature = txData.signature; // Use original signature
                return tx;
            });
    
            // Create new block with original values
            const block = new Block(
                blockData.index,
                transactions,
                blockData.previousHash,
                blockData.timestamp  // Use original timestamp
            );
            
            // Important: Set these values from the original block
            block.nonce = blockData.nonce;
            block.hash = blockData.hash;
            
            return block;
        } catch (error) {
            console.error(`Node ${this.port}: Error reconstructing block:`, error);
            throw error;
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
        return new Response(JSON.stringify(this.blockchain.chain), {
            headers: { "Content-Type": "application/json" }
        });
    }

    async handleGetPeers(req) {
        return new Response(JSON.stringify({
            peers: Array.from(this.peers.keys())
        }), {
            headers: { "Content-Type": "application/json" }
        });
    }

    async handleHealthCheck(req) {
        return new Response(JSON.stringify({
            status: "healthy",
            timestamp: Date.now(),
            blockHeight: this.blockchain.chain.length,
            peersCount: this.peers.size,
            lastBlockHash: this.blockchain.getLatestBlock().hash.substring(0, 10) + '...',
            pendingTransactions: this.blockchain.pendingTransactions.length
        }), {
            headers: { "Content-Type": "application/json" }
        });
    }

    async broadcastTransaction(transaction) {
        const promises = Array.from(this.peers.values()).map(peer => 
            fetch(`${peer}/transaction`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': process.env.NETWORK_SECRET
                },
                body: JSON.stringify(transaction)
            })
        );
        await Promise.all(promises);
    }

    async broadcastBlock(block) {
        const promises = Array.from(this.peers.keys()).map(async (peerAddress) => {
            try {
                console.log(`Node ${this.port}: Broadcasting block to peer ${peerAddress}`);
                const response = await fetch(`http://${peerAddress}/block`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-auth-token': process.env.NETWORK_SECRET,
                        'x-forwarded-host': `localhost:${this.port}` // Add sender information
                    },
                    body: JSON.stringify(block)
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

    async checkRateLimit(req) {
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

    async syncWithPeer(peerAddress) {
        try {
            console.log(`Node ${this.port}: Attempting to sync with peer ${peerAddress}`);
            const response = await fetch(`http://${peerAddress}/chain`, {
                headers: { 
                    'x-auth-token': process.env.NETWORK_SECRET,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`Failed to get chain from peer: ${response.status}`);
            }
            
            const peerChain = await response.json();
            console.log(`Node ${this.port}: Received chain of length ${peerChain.length} from peer`);
            
            // Reconstruct the chain with proper objects
            const reconstructedChain = peerChain.map(blockData => {
                // Reconstruct transactions first
                const transactions = blockData.transactions.map(txData => {
                    const tx = new Transaction(txData.sender, txData.recipient, txData.amount);
                    tx.timestamp = txData.timestamp;
                    tx.signature = txData.signature;
                    return tx;
                });
    
                // Then reconstruct the block
                const block = new Block(blockData.index, transactions, blockData.previousHash);
                block.timestamp = blockData.timestamp;
                block.nonce = blockData.nonce;
                block.hash = blockData.hash;
                return block;
            });
    
            // Validate the reconstructed chain
            if (this.blockchain.isValidChain(reconstructedChain)) {
                this.blockchain.chain = reconstructedChain;
                console.log(`Node ${this.port}: Successfully synchronized with peer ${peerAddress}. New chain height: ${reconstructedChain.length}`);
                return true;
            } else {
                throw new Error("Chain validation failed after reconstruction");
            }
        } catch (error) {
            console.error(`Node ${this.port}: Failed to sync with peer ${peerAddress}:`, error.message);
            return false;
        }
    }

    getBalance(address) {
        let balance = 0;
        
        // Check genesis allocations first
        const genesisBlock = this.blockchain.chain[0];
        if (genesisBlock) {
            for (const tx of genesisBlock.transactions) {
                if (tx.recipient === address) {
                    balance += tx.amount;
                }
            }
        }
        
        // Then check all other blocks
        for (const block of this.blockchain.chain.slice(1)) {
            for (const tx of block.transactions) {
                if (tx.sender === address) {
                    balance -= tx.amount;
                }
                if (tx.recipient === address) {
                    balance += tx.amount;
                }
            }
        }
        
        return balance;
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
    
            // Get all peer chains
            for (const [peerAddress] of this.peers) {
                try {
                    console.log(`Node ${this.port}: Syncing with peer ${peerAddress}`);
                    const response = await fetch(`http://${peerAddress}/chain`, {
                        headers: { 
                            'x-auth-token': process.env.NETWORK_SECRET,
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (!response.ok) continue;
                    
                    const peerChainData = await response.json();
                    
                    // Reconstruct the chain with proper Block objects
                    const reconstructedChain = peerChainData.map(blockData => {
                        // Reconstruct transactions first
                        const transactions = blockData.transactions.map(txData => {
                            const tx = new Transaction(txData.sender, txData.recipient, txData.amount);
                            tx.timestamp = txData.timestamp;
                            tx.signature = txData.signature;
                            return tx;
                        });
    
                        // Create new Block instance
                        const block = new Block(blockData.index, transactions, blockData.previousHash);
                        block.timestamp = blockData.timestamp;
                        block.nonce = blockData.nonce;
                        block.hash = blockData.hash;
                        return block;
                    });
    
                    if (reconstructedChain.length > maxHeight && 
                        this.blockchain.isValidChain(reconstructedChain)) {
                        longestChain = reconstructedChain;
                        maxHeight = reconstructedChain.length;
                        console.log(`Node ${this.port}: Found longer valid chain (${maxHeight} blocks)`);
                    }
                } catch (error) {
                    console.error(`Node ${this.port}: Failed to sync with peer ${peerAddress}:`, error.message);
                }
            }
    
            // Update our chain if we found a longer valid chain
            if (maxHeight > this.blockchain.chain.length) {
                this.blockchain.chain = longestChain;
                console.log(`Node ${this.port}: Updated chain to height ${maxHeight}`);
                return true;
            }
            return false;
        } catch (error) {
            console.error(`Node ${this.port}: Sync error:`, error.message);
            return false;
        }
    }

    async syncWithPeersX() {
        if (this.peers.size === 0) return;
        
        try {
            let longestChain = this.blockchain.chain;
            let maxHeight = longestChain.length;
    
            // Get all peer chains
            for (const [peerAddress] of this.peers) {
                try {
                    console.log(`Node ${this.port}: Syncing with peer ${peerAddress}`);
                    const response = await fetch(`http://${peerAddress}/chain`, {
                        headers: { 
                            'x-auth-token': process.env.NETWORK_SECRET,
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (!response.ok) continue;
                    
                    const peerChain = await response.json();
                    if (peerChain.length > maxHeight && this.blockchain.isValidChain(peerChain)) {
                        longestChain = peerChain;
                        maxHeight = peerChain.length;
                        console.log(`Node ${this.port}: Found longer valid chain (${maxHeight} blocks)`);
                    }
                } catch (error) {
                    console.error(`Node ${this.port}: Failed to sync with peer ${peerAddress}:`, error.message);
                }
            }
    
            // Update our chain if we found a longer valid chain
            if (maxHeight > this.blockchain.chain.length) {
                this.blockchain.chain = longestChain;
                console.log(`Node ${this.port}: Updated chain to height ${maxHeight}`);
                return true;
            }
            return false;
        } catch (error) {
            console.error(`Node ${this.port}: Sync error:`, error.message);
            return false;
        }
    }

    async mineIfNeeded() {
        if (this.blockchain.pendingTransactions.length > 0) {
            console.log(`Node ${this.port}: Mining block with ${this.blockchain.pendingTransactions.length} transactions`);
            
            try {
                const newBlock = this.blockchain.minePendingTransactions(this.nodeId);
                console.log(`Node ${this.port}: Mined new block ${newBlock.hash.substring(0, 10)}`);
                
                // Broadcast the new block
                await this.broadcastBlock(newBlock);
                console.log(`Node ${this.port}: Broadcasted block to peers`);
            } catch (error) {
                console.error(`Node ${this.port}: Mining failed:`, error);
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