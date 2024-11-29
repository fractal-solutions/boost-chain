import { Block } from "./block.js";
import { Transaction } from "./transaction.js";
import { Token } from "./token.js";
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
        //const rewardTx = new Transaction(null, minerAddress, this.miningReward);
        
        // Create new block with proper index
        const block = new Block(
            this.chain.length, // Use chain length as index instead of Date.now()
            [...this.pendingTransactions],
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
        try {
            if (!address) return 0;
            let balance = 0;
            
            // Process all blocks including genesis
            for (const block of this.chain) {
                if (!block || !block.transactions) continue;
                for (const tx of block.transactions) {
                    if (!tx || typeof tx.amount !== 'number') continue;
                    if (tx.sender === address) balance -= Number(tx.amount);
                    if (tx.recipient === address) balance += Number(tx.amount);
                }
            }
    
            // Add pending transactions if they exist
            if (Array.isArray(this.pendingTransactions)) {
                for (const tx of this.pendingTransactions) {
                    if (!tx || typeof tx.amount !== 'number') continue;
                    if (tx.sender === address) balance -= Number(tx.amount);
                    if (tx.recipient === address) balance += Number(tx.amount);
                }
            }
    
            return balance;
        } catch (error) {
            console.error('Error calculating balance:', error);
            return 0;
        }
    }
}
