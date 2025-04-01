import { SmartContract } from "./smartContract.js";
import { Transaction } from "./transaction.js";

export class SmartContractManager {
    constructor(blockchain) {
        this.contracts = new Map();
        this.blockchain = blockchain;
        this.eventLog = [];
        this.startContractMonitoring();
    }

    createContract(options) {
        const contract = new SmartContract(options);
        this.contracts.set(contract.contractId, contract);
        this.logEvent('CONTRACT_CREATED', contract.contractId, {
            creator: options.creator,
            timestamp: Date.now()
        });
        return contract;
    }

    getContract(contractId) {
        return this.contracts.get(contractId);
    }

    getAllContracts() {
        return Array.from(this.contracts.values());
    }

    getContractsByParticipant(address) {
        return Array.from(this.contracts.values()).filter(
            contract => contract.participants.includes(address) || 
                       contract.creator === address
        );
    }

    async executeScheduledPayment(contract) {
        if (contract.status !== 'ACTIVE') return;

        const payment = {
            from: contract.creator,
            to: contract.participants[0], // Assuming single recipient for now
            amount: contract.amount,
            timestamp: Date.now(),
            contractId: contract.contractId
        };

        try {
            // Create and execute transaction
            const transaction = new Transaction(
                payment.from,
                payment.to,
                payment.amount,
                payment.timestamp,
                'CONTRACT_PAYMENT'
            );

                                    // Create transaction via main blockchain API
                                    const txResult = await fetch('http://localhost:2222/txn', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                            'x-auth-token': process.env.NETWORK_SECRET
                                        },
                                        body: JSON.stringify({
                                            from: payment.from,
                                            to: payment.to,
                                            amount: payment.amount,
                                            type: 'CONTRACT_PAYMENT'
                                        })
                                    });
                
                                    if (!txResult.ok) {
                                        throw new Error('Failed to process initial contract payment');
                                    }
                
                                    

            //await this.blockchain.addTransaction(transaction);
            contract.addPayment(payment);
            
            this.logEvent('PAYMENT_EXECUTED', contract.contractId, payment);
            return payment;
        } catch (error) {
            this.logEvent('PAYMENT_FAILED', contract.contractId, {
                error: error.message,
                payment
            });
            throw error;
        }
    }

    logEvent(type, contractId, data) {
        this.eventLog.push({
            type,
            contractId,
            timestamp: Date.now(),
            data
        });
    }

    getEventLog(contractId = null) {
        if (contractId) {
            return this.eventLog.filter(event => event.contractId === contractId);
        }
        return this.eventLog;
    }

    startContractMonitoring() {
        //setInterval(() => {
            this.contracts.forEach(contract => {
                if (contract.status === 'ACTIVE' && 
                    Date.now() >= contract.nextPaymentDate) {
                    this.executeScheduledPayment(contract);
                }
            });
        //}, 60000); // Check every minute
    }

    terminateContract(contractId) {
        const contract = this.contracts.get(contractId);
        if (!contract) throw new Error('Contract not found');
        
        const result = contract.terminate();
        this.logEvent('CONTRACT_TERMINATED', contractId, {
            timestamp: Date.now()
        });
        return result;
    }
}