import { createSign, createVerify, createHash } from "crypto";

export class Transaction {
    constructor(sender, recipient, amount) {
        this.sender = sender;
        this.recipient = recipient;
        this.amount = amount;
        this.timestamp = Date.now();
        this.signature = "";
    }

    calculateHash() {
        const data = this.sender + this.recipient + this.amount + this.timestamp;
        return createHash("sha256").update(data).digest("hex");
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
        // Genesis transaction or mining reward
        if (this.sender === null) {
            return true;
        }

        // Regular transaction validation
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