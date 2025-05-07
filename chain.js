import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { Token } from "./token.js";
import { createHash } from "crypto";

export class Blockchain {
    constructor(genesisTransactions = [], existingChain = null) {
        // If we have an existing chain, use it
        if (existingChain && Array.isArray(existingChain) && existingChain.length > 0) {
            console.log(`Initializing blockchain with existing chain of ${existingChain.length} blocks`);
            this.chain = existingChain;
        } else {
            // Otherwise create a new chain with genesis block
            console.log('Creating new blockchain with genesis block');
            this.chain = [this.createGenesisBlock(genesisTransactions)];
        }

        this.pendingTransactions = [];
        this.minTransactionsPerBlock = 5; // Minimum transactions before mining (excluding reward)
        this.maxTransactionsPerBlock = 7; // Maximum transactions per block
        this.blockTimeTarget = 5000; // Target 10 seconds between blocks
        this.lastBlockTime = Date.now();

        this.difficulty = 2;
        this.miningReward = 0.01; 
        this.balanceCache = new Map();
        this.lastProcessedBlock = 0;

        // Checkpoint
        this.checkpoints = new Map(); // blockHeight -> blockHash
        this.checkpointInterval = 100; // Create checkpoint every 100 blocks
                
        // Create genesis checkpoint
        this.checkpoints.set(0, this.chain[0].hash);
    }

    createGenesisBlock(transactions = []) {
        const block = new Block(0, transactions, "0");
        block.timestamp = 0; // Fixed timestamp for genesis block
        block.nonce = 0;    // Fixed nonce for genesis block
        block.hash = block.calculateHash(); // Calculate hash after setting fixed values
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
            // Check if sender has enough balance including the fee
            const balance = this.getBalance(transaction.sender);
            if (balance < (transaction.amount)) {
                throw new Error("Insufficient balance (including transaction fee)");
            }
        }

        this.pendingTransactions.push(transaction);
    }

    shouldMineBlock() {
        const pendingCount = this.pendingTransactions.length;
        const timeSinceLastBlock = Date.now() - this.lastBlockTime;

        // More aggressive mining conditions for testing
        return (
            pendingCount >= this.minTransactionsPerBlock || 
            (pendingCount > 0 && timeSinceLastBlock >= this.blockTimeTarget) ||
            pendingCount >= this.maxTransactionsPerBlock  // Mine immediately if we hit max
        );
    }

    

    minePendingTransactions(minerAddress) {

        if (!this.shouldMineBlock()) {
            return null;
        }

        if (this.pendingTransactions.length === 0) {
            return null;
        }

        // Group related transactions (main tx + fee tx) together
        const blockTransactions = [];
        const processedHashes = new Set();
        
        for (const tx of this.pendingTransactions) {
            // Skip if we've already processed this transaction
            if (processedHashes.has(tx.calculateHash())) continue;
            
            // Add the main transaction
            blockTransactions.push(tx);
            processedHashes.add(tx.calculateHash());
            
            // Find and add the related fee transaction if it exists
            const relatedFee = this.pendingTransactions.find(feeTx => 
                feeTx.type === "FEE" && 
                feeTx.sender === tx.sender && 
                feeTx.timestamp >= tx.timestamp && 
                feeTx.timestamp - tx.timestamp < 1000 // Within 1 second
            );
            
            if (relatedFee) {
                blockTransactions.push(relatedFee);
                processedHashes.add(relatedFee.calculateHash());
            }
            
            // Check if we've reached block size limit
            if (blockTransactions.length >= this.maxTransactionsPerBlock - 1) {
                break;
            }
        }

        // Select transactions for the block (including reward)
        // const selectedTransactions = [
        //     ...this.pendingTransactions.slice(0, this.maxTransactionsPerBlock - 1)
        // ];

        const block = new Block(
            this.chain.length,
            blockTransactions,
            this.getLatestBlock().hash
        );
    
        block.mineBlock(this.difficulty);
        
        console.log('Block mined:', block.hash);
        this.chain.push(block);
    
        // Create checkpoint if needed
        if (this.chain.length % this.checkpointInterval === 0) {
            this.checkpoints.set(this.chain.length - 1, block.hash);
            console.log(`Created checkpoint at height ${this.chain.length - 1}`);
        }
    
        // Remove mined transactions from pending
        //this.pendingTransactions = this.pendingTransactions.slice(selectedTransactions.length);

        // Remove processed transactions from pending
        const processedTxs = new Set(blockTransactions.map(tx => tx.calculateHash()));
        this.pendingTransactions = this.pendingTransactions.filter(tx => 
            !processedTxs.has(tx.calculateHash())
        );
        
        return block;
    }

    isValidChainSegment(chain, startHeight, endHeight) {
        try {
            for (let i = startHeight; i < endHeight; i++) {
                const block = chain[i];
                const previousBlock = chain[i - 1];

                // Verify block connection
                if (block.previousHash !== previousBlock.hash) {
                    console.log(`Invalid block connection at height ${i}`);
                    return false;
                }

                // Verify block hash
                const calculatedHash = block.calculateHash();
                if (block.hash !== calculatedHash) {
                    console.log(`Invalid block hash at height ${i}:`, {
                        stored: block.hash.substring(0, 10),
                        calculated: calculatedHash.substring(0, 10)
                    });
                    return false;
                }

                // Verify transactions
                for (const tx of block.transactions) {
                    if (tx.type !== "FEE") return true;
                    if (!tx.isValid() && tx.sender !== null) {
                        console.log(`Invalid transaction in block ${i}`);
                        return false;
                    }
                }
            }
            return true;
        } catch (error) {
            console.error('Error validating chain segment:', error);
            return false;
        }
    }

    isValidChain(chain) {
        try {
            // If new chain is shorter, reject it
            if (chain.length < this.chain.length) {
                console.log('Rejecting shorter chain');
                return false;
            }

            // First, compare genesis blocks by hash
            const genesisBlock = chain[0];
            const ourGenesis = this.chain[0];
            
            if (genesisBlock.hash !== ourGenesis.hash) {
                console.log('Genesis block mismatch:', {
                    received: genesisBlock.hash.substring(0, 10),
                    expected: ourGenesis.hash.substring(0, 10)
                });
                return false;
            }

            // // Find the latest common checkpoint
            // let lastCheckpointHeight = 0;
            // for (const [height, hash] of this.checkpoints) {
            //     if (height >= chain.length) break;
            //     if (chain[height].hash === hash) {
            //         lastCheckpointHeight = height;
            //     } else {
            //         console.log(`Checkpoint mismatch at height ${height}`);
            //         return false;
            //     }
            // }

            // Find the highest common checkpoint
            let lastCheckpointHeight = this.chain.length - 1;
            while (lastCheckpointHeight > 0) {
                if (this.checkpoints.has(lastCheckpointHeight) && 
                    chain[lastCheckpointHeight]?.hash === this.checkpoints.get(lastCheckpointHeight)) {
                    break;
                }
                lastCheckpointHeight--;
            }

            // Validate only the segment after the last checkpoint
            console.log(`Validating chain from checkpoint at height ${lastCheckpointHeight}`);
            return this.isValidChainSegment(chain, lastCheckpointHeight + 1, chain.length);

        } catch (error) {
            console.error('Error validating chain:', error);
            return false;
        }
    }

    isValidChainX(chain) {
        try{
            // If new chain is shorter, reject it
            if (chain.length < this.chain.length) {
                console.log('Rejecting shorter chain');
                return false;
            }
            
            // First, compare genesis blocks by hash
            const genesisBlock = chain[0];
            const ourGenesis = this.chain[0];
            
            if (genesisBlock.hash !== ourGenesis.hash) {
                console.log('Genesis block mismatch:', {
                    received: genesisBlock.hash.substring(0, 10),
                    expected: ourGenesis.hash.substring(0, 10)
                });
                return false;
            }
        
            // Check the rest of the chain
            for (let i = 1; i < chain.length; i++) {
                const block = chain[i];
                const previousBlock = chain[i - 1];
        
                if (block.previousHash !== previousBlock.hash) {
                    console.log(`Invalid block connection at height ${i}`);
                    return false;
                }
        
                // Verify block hash
                const calculatedHash = block.calculateHash();
                if (block.hash !== calculatedHash) {
                    console.log(`Invalid block hash at height ${i}:`, {
                        stored: block.hash.substring(0, 10),
                        calculated: calculatedHash.substring(0, 10)
                    });
                    return false;
                }
        
                for (const tx of block.transactions) {
                    if (!tx.isValid() && tx.sender !== null) {
                        console.log(`Invalid transaction in block ${i}`);
                        return false;
                    }
                }
            }
            return true;
        } catch (error) {
            console.error('Error validating chain:', error);
            return false;
        }
    }

    isValidBlock(block) {
        try {
            const blockInstance = block instanceof Block ? block : new Block(block.index, [], block.previousHash);
            blockInstance.timestamp = block.timestamp;
            blockInstance.nonce = block.nonce;
            blockInstance.hash = block.hash;
    
            blockInstance.transactions = block.transactions.map(tx => {
                if (tx instanceof Transaction) return tx;
                const reconstructedTx = new Transaction(tx.sender, tx.recipient, tx.amount);
                reconstructedTx.timestamp = tx.timestamp;
                reconstructedTx.signature = tx.signature;
                return reconstructedTx;
            });
    
            const previousBlock = this.chain[this.chain.length - 1];
    
            if (blockInstance.previousHash !== previousBlock.hash) {
                console.log('Block does not connect to previous block');
                return false;
            }
    
            const calculatedHash = blockInstance.calculateHash();
            if (calculatedHash !== blockInstance.hash) {
                console.log('Block hash verification failed:', {
                    stored: blockInstance.hash.substring(0, 10),
                    calculated: calculatedHash.substring(0, 10)
                });
                return false;
            }
    
            for (const tx of blockInstance.transactions) {
                if (!tx.isValid() && tx.sender !== null) {
                    console.log('Invalid transaction in block');
                    return false;
                }
            }
    
            return true;
        } catch (error) {
            console.error('Error validating block:', error);
            return false;
        }
    }

    isValidBlockX(block) {
        try {
            // Convert plain object to Block instance if needed
            const blockInstance = block instanceof Block ? block : new Block(block.index, [], block.previousHash);
            blockInstance.timestamp = block.timestamp;
            blockInstance.nonce = block.nonce;
            blockInstance.hash = block.hash;
    
            // Reconstruct Transaction objects
            blockInstance.transactions = block.transactions.map(tx => {
                if (tx instanceof Transaction) return tx;
                const reconstructedTx = new Transaction(tx.sender, tx.recipient, tx.amount);
                reconstructedTx.timestamp = tx.timestamp;
                reconstructedTx.signature = tx.signature;
                reconstructedTx.nonce = tx.nonce;
                reconstructedTx.type = tx.type;
                return reconstructedTx;
            });
    
            // Get the previous block from the chain
            const previousBlock = this.chain[this.chain.length - 1];
            
            // Rest of validation logic...
            if (blockInstance.previousHash !== previousBlock.hash) {
                console.log('Block does not connect to previous block');
                return false;
            }
    
            // Verify proof of work
            const hashStartsWithZeros = blockInstance.hash.startsWith('0'.repeat(this.difficulty));
            if (!hashStartsWithZeros) {
                console.log('Block does not meet difficulty requirement');
                return false;
            }
    
            // Verify block hash matches its contents
            const calculatedHash = blockInstance.calculateHash();
            if (calculatedHash !== blockInstance.hash) {
                console.log('Block hash verification failed:', {
                    stored: blockInstance.hash.substring(0, 10),
                    calculated: calculatedHash.substring(0, 10)
                });
                return false;
            }
    
            // Verify all transactions
            for (const tx of blockInstance.transactions) {
                if (!tx.isValid() && tx.sender !== null) {
                    console.log('Invalid transaction in block');
                    return false;
                }
            }
    
            return true;
        } catch (error) {
            console.error('Error validating block:', error);
            return false;
        }
    }

    getBalance(address) {
        // Use cached balance and only process new blocks
        let balance = this.balanceCache.get(address) || 0;
        
        for (let i = this.lastProcessedBlock; i < this.chain.length; i++) {
            const block = this.chain[i];
            for (const tx of block.transactions) {
                if (tx.sender === address) balance -= tx.amount;
                if (tx.recipient === address) balance += tx.amount;
            }
        }
        
        this.balanceCache.set(address, balance);
        this.lastProcessedBlock = this.chain.length;
        return balance;
    }
}
