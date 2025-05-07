import { createHash } from "crypto";

export class Block {
    constructor(index, transactions, previousHash = '', timestamp = Date.now()) {
        this.index = index;
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.nonce = 0;
        this._txHashesCache = null;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        // We need to ensure consistent string representation of transactions
        const txString = this.transactions.map(tx => ({
            sender: tx.sender,
            recipient: tx.recipient,
            amount: tx.amount,
            timestamp: tx.timestamp,
            type: tx.type || 'TRANSFER'
            // Note: We don't include signature in hash calculation
        }));

        return createHash('sha256')
            .update(
                this.index +
                this.timestamp +
                JSON.stringify(txString) + // Use consistent transaction representation
                this.previousHash +
                this.nonce
            )
            .digest('hex');
    }

    calculateHashX() {
        try {
            // Ensure consistent transaction serialization
            const txData = this.transactions.map(tx => ({
                sender: tx.sender,
                recipient: tx.recipient,
                amount: Number(tx.amount),
                timestamp: tx.timestamp,
                signature: tx.signature
            }));
    
            const data = JSON.stringify({
                index: this.index,
                previousHash: this.previousHash,
                timestamp: this.timestamp,
                transactions: txData,
                nonce: this.nonce
            });
    
            return createHash("sha256").update(data).digest("hex");
        } catch (error) {
            console.error('Error calculating block hash:', error);
            throw error;
        }
    }

    isValid() {
        try {
            // Check block hash
            const calculatedHash = this.calculateHash();
            if (this.hash !== calculatedHash) {
                console.error('Block hash mismatch:', {
                    stored: this.hash.substring(0, 10),
                    calculated: calculatedHash.substring(0, 10),
                    blockHeight: this.index
                });
                return false;
            }
    
            // Validate all transactions
            for (const tx of this.transactions) {
                if (!tx.isValid()) {
                    console.error('Invalid transaction in block:', {
                        blockHash: this.hash.substring(0, 10),
                        txHash: tx.calculateHash().substring(0, 10)
                    });
                    return false;
                }
            }
    
            return true;
        } catch (error) {
            console.error('Error validating block:', error);
            return false;
        }
    }

    mineBlock(difficulty) {
        while (!this.hash.startsWith("0".repeat(difficulty))) {
            this.nonce++;
            this.hash = this.calculateHash();
        }
    }
} 