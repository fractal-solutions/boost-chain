import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { Token } from "./token.js";
import { createHash } from "crypto";

export class Blockchain {
    constructor(genesisTransactions = []) {
        this.chain = [this.createGenesisBlock(genesisTransactions)];
        this.pendingTransactions = [];
        this.difficulty = 2;
        this.miningReward = 0; // Define mining reward
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
        // Validate transaction
        if (!transaction.isValid()) {
            throw new Error("Invalid transaction");
        }

        // Check balance using only confirmed transactions
        if (transaction.sender !== null) {
            const balance = this.getBalance(transaction.sender);
            if (balance < transaction.amount) {
                throw new Error("Insufficient balance");
            }
        }

        this.pendingTransactions.push(transaction);
    }

    minePendingTransactions(minerAddress) {
        // Create mining reward transaction
        const rewardTx = new Transaction(null, minerAddress, this.miningReward);
        
        // Create new block with proper index
        const block = new Block(
            this.chain.length, // Use chain length as index instead of Date.now()
            [...this.pendingTransactions, rewardTx],
            this.getLatestBlock().hash
        );
    
        // Mine the block
        block.mineBlock(this.difficulty);
        
        console.log('Block mined:', block.hash);
        this.chain.push(block);
    
        this.pendingTransactions = [];
        
        return block;
    }

    isValidChain(chain) {
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
    
            if (block.hash !== block.calculateHash()) {
                console.log(`Invalid block hash at height ${i}`);
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
    }

    isValidBlock(block) {
        try {
            // Convert plain object to Block instance if needed
            const blockInstance = block instanceof Block ? block : new Block(
                block.index,
                block.transactions.map(tx => new Transaction(tx.sender, tx.recipient, tx.amount, tx.timestamp, tx.signature)),
                block.previousHash,
                block.timestamp,
                block.nonce
            );
    
            // Check block index
            if (blockInstance.index !== this.chain.length) {
                console.log(`Invalid block index. Expected ${this.chain.length}, got ${blockInstance.index}`);
                return false;
            }
    
            // Check if block connects to our chain
            const latestBlock = this.getLatestBlock();
            if (blockInstance.previousHash !== latestBlock.hash) {
                console.log('Block does not connect to latest block');
                return false;
            }
    
            // Verify proof of work
            const hashStartsWithZeros = blockInstance.hash.substring(0, this.difficulty) === '0'.repeat(this.difficulty);

            console.log('Block validation details:', {
                hash: blockInstance.hash,
                difficulty: this.difficulty,
                requiredPrefix: '0'.repeat(this.difficulty),
                actualPrefix: blockInstance.hash.substring(0, this.difficulty),
                meetsRequirement: hashStartsWithZeros
            });
            
            if (!hashStartsWithZeros) {
                console.log('Block does not meet difficulty requirement');
                return false;
            }
    
            // Verify block hash matches its contents
            const calculatedHash = blockInstance.calculateHash();
            if (block.hash !== calculatedHash) {
                console.log('Block hash mismatch:', {
                    received: block.hash.substring(0, 10),
                    calculated: calculatedHash.substring(0, 10)
                });
                return false;
            }
    
            // Verify all transactions in the block
            for (const transaction of blockInstance.transactions) {
                if (!transaction.isValid() && transaction.sender !== null) {
                    console.log('Transaction validation failed');
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
        let balance = 0;

        // Process all blocks including genesis
        for (const block of this.chain) {
            for (const transaction of block.transactions) {
                if (transaction.sender === address) {
                    balance -= transaction.amount;
                }
                if (transaction.recipient === address) {
                    balance += transaction.amount;
                }
            }
        }

        // Do NOT include pending transactions in balance calculation
        // This ensures balances only reflect confirmed transactions

        return balance;
    }
}
