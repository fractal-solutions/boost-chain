export class Token {
    constructor(initialSupply) {
        this.totalSupply = initialSupply;
        this.balances = { "platform": initialSupply };
    }

    transfer(sender, recipient, amount) {
        if (!this.balances[sender] || this.balances[sender] < amount) {
            throw new Error("Insufficient balance");
        }

        this.balances[sender] -= amount;
        this.balances[recipient] = (this.balances[recipient] || 0) + amount;
        return true;
    }

    mint(address, amount) {
        this.totalSupply += amount;
        this.balances[address] = (this.balances[address] || 0) + amount;
    }

    burn(address, amount) {
        if (!this.balances[address] || this.balances[address] < amount) {
            throw new Error("Insufficient balance to burn");
        }

        this.balances[address] -= amount;
        this.totalSupply -= amount;
    }

    getBalance(address) {
        return this.balances[address] || 0;
    }
} 