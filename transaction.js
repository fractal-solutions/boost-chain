import { createSign, createVerify, createHash } from "crypto";

export class Transaction {
    constructor(sender, recipient, amount, timestamp = Date.now(), type = "TRANSFER") {
        this.sender = sender;
        this.recipient = recipient;
        this.amount = amount;
        this.timestamp = timestamp;
        this.signature = "";
        this.type = type;
    }

    calculateHashX() {
        const data = JSON.stringify({
            sender: this.sender,
            recipient: this.recipient,
            amount: this.amount,
            timestamp: this.timestamp,
            type: this.type  // Add this line
        });
        return createHash("sha256").update(data).digest("hex");
    }

    calculateHash() {
        const data = this.sender + this.recipient + this.amount + this.timestamp;
        return createHash("sha256").update(data).digest("hex");
    }

    signTransaction(privateKey) {
        if (!privateKey) {
            throw new Error("No private key provided");
        }
    
        const hash = this.calculateHash();
        const sign = createSign("SHA256");
        sign.update(hash);
        this.signature = sign.sign(privateKey, "hex");
        return this.signature;
    }

    signTransactionX(privateKey) {
        if (!privateKey) {
            throw new Error("No private key provided");
        }

        const sign = createSign("SHA256");
        sign.update(this.calculateHash());
        this.signature = sign.sign(privateKey, "hex");
    }

    isValid() {
        if (this.skipSignatureValidation || this.type === "FEE") {
            return true;
        }
        // Genesis transaction or mining reward
        if (this.sender === null) {
            return true;
        }

        // Regular transaction validation
        if (!this.signature || this.signature.length === 0) {
            console.log("Transaction validation failed: Missing signature");
            throw new Error("No signature in this transaction");
        }

        try {
            const verify = createVerify("SHA256");
            const hash = this.calculateHash();
            // console.log("Transaction validation details:", {
            //     hash: hash,
            //     signatureLength: this.signature.length,
            //     senderKeyLength: this.sender.length,
            //     amount: this.amount,
            //     timestamp: this.timestamp
            // });
            
            verify.update(hash);
            const isValidSignature = verify.verify(this.sender, this.signature, "hex");
            
            if (!isValidSignature) {
                console.log("Transaction validation failed: Signature verification failed");
                console.log("Verification inputs:", {
                    hash: hash,
                    signature: this.signature.substring(0, 32) + "...",
                    publicKey: this.sender.substring(0, 32) + "..."
                });
            }
            
            return isValidSignature;
        } catch (error) {
            console.error("Transaction verification error:", error.message);
            console.error("Full error:", error);
            console.error("Transaction details:", {
                sender: this.sender?.substring(0, 32) + "...",
                recipient: this.recipient?.substring(0, 32) + "...",
                amount: this.amount,
                timestamp: this.timestamp
            });
            return false;
        }
    }
} 