### Specification for a Custom Blockchain System with ERC-20-Like Token in JavaScript

**Objective**  
Design and implement a standalone blockchain system in JavaScript that supports token-based functionality similar to ERC-20. The blockchain will be node-based, meaning each instance is a node, with functionality for creating and verifying blocks, handling transactions, and managing tokens.

---

### System Architecture

1. **Blockchain Core**
   - A chain of blocks, each containing:
     - Block index.
     - Timestamp.
     - List of transactions.
     - Hash of the previous block.
     - Current block hash.
     - Nonce for proof-of-work.
   - Consensus mechanism: **Proof-of-Work (PoW)** for simplicity.
   - Node functionality: Nodes will validate and propagate blocks and transactions using secure communication protocols.

2. **Token Functionality**
   - Integrated into the Blockchain class, managing tokens without a separate Token class.
   - Functions to manage tokens:
     - Transferring tokens between addresses.
     - Balances associated with addresses.
     - Minting new tokens.
     - Burning existing tokens.
   - Utilizes built-in cryptographic utilities for security.

---

### Functional Requirements

1. **Blockchain Functions**
   - **Create Genesis Block**: Initialize the blockchain with the first block.
   - **Add Blocks**: Append validated blocks to the chain after Proof-of-Work.
   - **Transaction Validation**: Verify signatures and balances before adding transactions to a block.
   - **Proof-of-Work**: Achieve consensus by solving cryptographic puzzles.
   - **Sync Across Nodes**: Maintain identical copies of the chain across nodes through synchronization protocols.

2. **Token Functions**
   - **Transfer**: Send tokens between addresses, ensuring sufficient balance.
   - **Mint**: Create new tokens and assign them to specific addresses.
   - **Burn**: Destroy tokens from specific addresses to reduce total supply.
   - **Balance Inquiry**: Check the token balance of an address.

3. **Node Functions**
   - Serve as an independent blockchain instance.
   - Broadcast and receive transactions and blocks to/from other nodes securely.
   - Validate incoming transactions and blocks before processing.
   - Maintain secure communication using authorization tokens.

---

### Security Mechanisms

To ensure the security and integrity of the blockchain system, the following mechanisms are implemented:

1. **Authentication and Authorization**
   - **x-auth-token Headers**: All inter-node communications include an `x-auth-token` header containing a shared `NETWORK_SECRET`. This token verifies the authenticity of the requesting node.
   - **Role-Based Access Control**: Nodes are assigned specific roles (e.g., Controller, SME, Validator) which determine their permissions within the network.

2. **Data Integrity**
   - **Cryptographic Hashing**: Each block contains a hash of its contents, ensuring that any tampering with block data can be detected.
   - **Digital Signatures**: Transactions are signed using HMAC-SHA256 to verify the origin and integrity of transaction data.

3. **Prevention of Replay Attacks**
   - **Nonces**: Unique nonces are used in deposit and withdrawal transactions to prevent replay attacks. Once a nonce is used, it is stored and cannot be reused within a specified time window.

4. **Rate Limiting**
   - **Deposit Rate Limiting**: Limits the number of deposit transactions per recipient within a given time frame to thwart abuse and ensure fair usage.

5. **Secure Communication**
   - **Encrypted Channels**: Nodes communicate over secure channels (e.g., HTTPS) to protect data in transit from eavesdropping and tampering.

6. **Consensus Security**
   - **Proof-of-Work (PoW)**: The PoW consensus mechanism makes it computationally expensive to alter the blockchain, thereby securing the network against attacks such as double-spending.

7. **Periodic Data Cleanup**
   - **Nonce and Rate Limit Data Cleanup**: Old nonces and outdated rate limit data are periodically cleaned to maintain optimal performance and security.

8. **Synchronization Protocols**
   - **Chain Synchronization**: Nodes regularly synchronize their blockchain state with peers to ensure consistency and detect any discrepancies caused by malicious actors.

By integrating these security measures, the blockchain system maintains robustness against various attack vectors and ensures reliable and trustworthy operations across all nodes.

---


### Deploying Nodes

To deploy nodes in the blockchain network, instantiate the `Node` class with the appropriate configurations. Below are examples of deploying a **Controller Node** and a **Validator Node**.

#### Controller Node

A Controller Node manages the network, handles high-level operations, and oversees functionalities such as minting tokens and managing rate limits.

```javascript
const node = new Node({
    host: 'localhost',
    port: 3001,
    nodeType: NodeType.CONTROLLER,
    seedNodes: ['http://localhost:3002', 'http://localhost:3003']
});
```

**Configuration Options:**

- `host`: Specifies the hostname or IP address where the node will run. For local deployments, use `'localhost'`.
- `port`: Defines the port number on which the node will listen for incoming connections.
- `nodeType`: Determines the role of the node. Use `NodeType.CONTROLLER` for Controller Nodes.
- `seedNodes`: An array of seed node URLs that the Controller Node will use to discover and connect with other peers in the network.

#### Validator Node

Validator Nodes are responsible for validating transactions and blocks, ensuring the integrity and security of the blockchain.

```javascript
const node = new Node({
    host: 'validator1.blockchain.example.com',
    port: 443,
    protocol: 'https',
    nodeType: NodeType.VALIDATOR,
    seedNodes: [
        'https://seed1.blockchain.example.com',
        'https://seed2.blockchain.example.com'
    ]
});
```

**Configuration Options:**

- `host`: The domain name or IP address of the Validator Node. For production environments, use a fully qualified domain name.
- `port`: The port number on which the Validator Node will accept secure (HTTPS) connections.
- `protocol`: Specifies the communication protocol. Use `'https'` to ensure encrypted communication in production.
- `nodeType`: Sets the role of the node. Use `NodeType.VALIDATOR` for Validator Nodes.
- `seedNodes`: An array of seed node URLs that the Validator Node will connect to for network synchronization and peer discovery.

#### Deployment Steps

1. **Install Dependencies**: Ensure that all necessary dependencies are installed by running:
   ```bash
   npm install
   ```

2. **Configure Environment Variables**: Set up the required environment variables, such as `NETWORK_SECRET`, to secure inter-node communications.

3. **Initialize the Node**: Use one of the above configurations to instantiate the `Node` class based on the desired role.

4. **Start the Node**: Launch the node by running:
   ```bash
   node node.js
   ```
   Replace `node.js` with the actual entry point of your application if different.

5. **Monitor Logs**: Keep an eye on the console logs to ensure that the node starts correctly and connects to the specified seed nodes.

By following these configurations and steps, you can effectively deploy Controller and Validator Nodes within your blockchain network, ensuring a secure and well-synchronized system.




### Implementation Details

#### 1. **Blockchain Class**
A robust blockchain system with block creation, transaction handling, and token management.

```javascript
import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { createHash } from "crypto";

export class Blockchain {
    constructor(genesisTransactions = []) {
        this.chain = [this.createGenesisBlock(genesisTransactions)];
        this.pendingTransactions = [];
        this.difficulty = 2;
        this.miningReward = 0.01; // Define mining reward
    }

    createGenesisBlock(transactions = []) {
        const block = new Block(0, transactions, "0");
        block.timestamp = 0; // Fixed timestamp for genesis block
        block.nonce = 0;
        block.hash = block.calculateHash();
        return block;
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    addTransaction(transaction) {
        if (!transaction.isValid()) {
            throw new Error("Invalid transaction");
        }

        if (transaction.sender !== null) {
            const balance = this.getBalance(transaction.sender);
            if (balance < transaction.amount) {
                throw new Error("Insufficient balance");
            }
        }

        this.pendingTransactions.push(transaction);
    }

    minePendingTransactions(minerAddress) {
        const rewardTx = new Transaction(null, minerAddress, this.miningReward);
        this.pendingTransactions.push(rewardTx);

        const block = new Block(
            this.chain.length,
            [...this.pendingTransactions],
            this.getLatestBlock().hash
        );

        block.mineBlock(this.difficulty);

        console.log('Block mined:', block.hash);
        this.chain.push(block);

        this.pendingTransactions = [];
        
        return block;
    }

    isValidChain(chain) {
        const genesisBlock = chain[0];
        const ourGenesis = this.chain[0];
        
        if (genesisBlock.hash !== ourGenesis.hash) {
            console.log('Genesis block mismatch.');
            return false;
        }

        for (let i = 1; i < chain.length; i++) {
            const currentBlock = chain[i];
            const previousBlock = chain[i - 1];

            if (currentBlock.previousHash !== previousBlock.hash) {
                console.log(`Invalid previous hash at block ${i}`);
                return false;
            }

            if (currentBlock.hash !== currentBlock.calculateHash()) {
                console.log(`Invalid hash at block ${i}`);
                return false;
            }

            for (const tx of currentBlock.transactions) {
                if (!tx.isValid() && tx.sender !== null) {
                    console.log(`Invalid transaction in block ${i}`);
                    return false;
                }
            }
        }

        return true;
    }

    getBalance(address) {
        let balance = 0;

        for (const block of this.chain) {
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
}
```

---

#### 2. **Transaction Class**
Define a transaction structure with signing and validation.

```javascript
import { createSign, createVerify } from "crypto";

export class Transaction {
    constructor(sender, recipient, amount) {
        this.sender = sender;
        this.recipient = recipient;
        this.amount = amount;
        this.timestamp = Date.now();
        this.signature = "";
    }

    calculateHash() {
        return createHash("sha256")
            .update(this.sender + this.recipient + this.amount + this.timestamp)
            .digest("hex");
    }

    signTransaction(privateKey) {
        if (!privateKey) {
            throw new Error("No private key provided");
        }

        const sign = createSign("SHA256");
        sign.update(this.calculateHash());
        this.signature = sign.sign(privateKey, "hex");
    }

    isValid() {
        if (this.sender === null) return true; // Mining reward

        if (!this.signature || this.signature.length === 0) {
            throw new Error("No signature in this transaction");
        }

        try {
            const verify = createVerify("SHA256");
            verify.update(this.calculateHash());
            return verify.verify(this.sender, this.signature, "hex");
        } catch (error) {
            console.error("Verification error:", error.message);
            return false;
        }
    }
}
```

---

#### 3. **Block Class**
Define the structure and mining mechanism of a block.

```javascript
import { createHash } from "crypto";

export class Block {
    constructor(index, transactions, previousHash = "") {
        this.index = typeof index === 'number' ? index : 0;
        this.timestamp = Date.now();
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return createHash("sha256")
            .update(
                this.index +
                this.previousHash +
                this.timestamp +
                JSON.stringify(this.transactions) +
                this.nonce
            )
            .digest("hex");
    }

    mineBlock(difficulty) {
        while (!this.hash.startsWith("0".repeat(difficulty))) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        console.log(`Block mined: ${this.hash}`);
    }
}
```

---

#### 4. **Node Functionality**
A node to maintain blockchain data and handle requests using Bun.js.

```javascript
import { Blockchain } from "./chain.js";
import { Transaction } from "./transaction.js";
import { serve } from "bun";
import { createHmac } from "crypto";

export class Node {
    constructor(port, peers = [], options = {}) {
        this.blockchain = new Blockchain(options.genesisTransactions);
        this.port = port;
        this.peers = peers;
        this.nodeType = options.nodeType || "DEFAULT";
        this.networkSecret = process.env.NETWORK_SECRET;
        this.setupServer();
    }

    setupServer() {
        serve({
            port: this.port,
            fetch: async (req) => {
                const url = new URL(req.url);
                const path = url.pathname;

                // Authorization
                const authToken = req.headers.get('x-auth-token');
                if (authToken !== this.networkSecret) {
                    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403 });
                }

                switch (path) {
                    case "/transaction":
                        return this.handleTransaction(req);
                    case "/block":
                        return this.handleBlock(req);
                    case "/chain":
                        return this.handleChain(req);
                    // Add more routes as needed
                    default:
                        return new Response(JSON.stringify({ error: "Not found" }), { status: 404 });
                }
            },
        });

        console.log(`Node running on port ${this.port}`);
    }

    async handleTransaction(req) {
        try {
            const { sender, recipient, amount, signature } = await req.json();
            const transaction = new Transaction(sender, recipient, amount);
            transaction.signature = signature;

            this.blockchain.addTransaction(transaction);
            await this.broadcastTransaction(transaction);
            return new Response(JSON.stringify({ message: "Transaction added" }), { status: 201 });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), { status: 400 });
        }
    }

    async handleBlock(req) {
        try {
            const blockData = await req.json();
            // Validate and add block
            // Implementation details...
            return new Response(JSON.stringify({ message: "Block added" }), { status: 201 });
        } catch (error) {
            return new Response(JSON.stringify({ error: error.message }), { status: 400 });
        }
    }

    async handleChain(req) {
        return new Response(JSON.stringify(this.blockchain.chain), { status: 200 });
    }

    async broadcastTransaction(transaction) {
        for (const peer of this.peers) {
            await fetch(`http://${peer}/transaction`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-auth-token': this.networkSecret
                },
                body: JSON.stringify(transaction)
            });
        }
    }

    // Additional methods for handling blocks, syncing, etc.
}

```

---

### Additional Notes
- Utilize **Bun.js**'s built-in libraries from [Bun.sh](https://bun.sh) such as `Bun.serve` instead of Express for handling HTTP requests.
- Ensure secure communication between nodes using `x-auth-token` headers with a shared `NETWORK_SECRET`.
- Focus on maintaining simplicity and avoiding unnecessary abstractions.
- Implement clear and efficient communication protocols between nodes to ensure decentralized functionality and consensus.





This system provides the foundation for my platform's blockchain.

