import { SmartContract } from "./smartContract.js";
import { Transaction } from "./transaction.js";
import jwt from "jsonwebtoken";
import { JWT_SECRET, ENCRYPTION_KEY } from './config.js';
process.env.NETWORK_SECRET = 'test-secret-123';

export class SmartContractManager {
    constructor(blockchain) {
        this.contracts = new Map();
        this.blockchain = blockchain;
        this.eventLog = [];
        this.startContractMonitoring();

        // Generate service token on initialization
        this.serviceToken = jwt.sign(
            {
                id: 'smart-contract-service',
                role: 'SERVICE',
                permissions: ['execute_contract_payment', 'sign_transaction'],
                type: 'SERVICE_TOKEN'
            },
            process.env.NETWORK_SECRET,
            { expiresIn: '1y' } // Long-lived token for service
        );
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

    generateToken(user) {
        return jwt.sign(
            {
                id: user.id,
                role: user.role,
                publicKey: user.publicKey
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
    }

    generateContractToken(user, contractEndDate, contractId) {  // Add contractId parameter
        // Calculate seconds until contract end
        const now = Date.now();
        const endDate = Number(contractEndDate);
        const secondsUntilEnd = Math.floor((endDate - now) / 1000);
        const expiresIn = Math.min(Math.max(secondsUntilEnd, 60), 365 * 24 * 60 * 60);
    
        return jwt.sign({
            id: user.id,
            role: user.role,
            publicKey: user.publicKey,
            contractId: contractId,  // Include contract ID in token
            permissions: ['execute_contract_payment']
        }, JWT_SECRET, { expiresIn });
    }

    async executeScheduledPayment(contract) {
        if (contract.status !== 'ACTIVE') return;

        try {
            // Get user info from boost-users service
            const userResponse = await fetch('http://localhost:2225/user/by-public-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    publicKey: contract.creator.publicKey
                })
            });

            if (!userResponse.ok) {
                throw new Error('Failed to fetch user information');
            }

            const rawResponse = await userResponse.text();
            console.log('Raw user response:', rawResponse);

            const balanceRes = await fetch(
                `http://localhost:3001/balance?address=${encodeURIComponent(contract.creator.publicKey)}`,
                { headers: { 'x-auth-token': process.env.NETWORK_SECRET }}
            );
            const { balance } = await balanceRes.json();
            const requiredAmount = Number(contract.amount) * 1.01; // Amount + 1% fee
    
            if (balance < requiredAmount) {
                throw new Error(`Insufficient balance: Required ${requiredAmount}, Available ${balance}`);
            }

            const userData = JSON.parse(rawResponse);
            if (!userData.success) {
                throw new Error(userData.error || 'User not found');
            }

            // Generate contract-specific token
            const contractToken = this.generateContractToken(
                userData.data,
                contract.endDate,
                contract.contractId  // Pass contract ID
            );
            // Create and sign transaction
            const transaction = new Transaction(
                contract.creator.publicKey,
                contract.participants[0].publicKey,
                Number(contract.amount),
                Date.now(),
                'CONTRACT_PAYMENT',
            );

            // Sign transaction with creator's private key
            let signature;
            try {
                signature = transaction.signTransaction(contract.creator.privateKey);
            } catch (signError) {
                console.error('Signature creation error:', signError);
                throw new Error(`Failed to sign transaction: ${signError.message}`);
            }

            console.log('Executing payment with:', {
                from: contract.creator.publicKey.substring(0, 32) + '...',
                hasPrivateKey: !!contract.creator.privateKey,
                to: contract.participants[0].publicKey.substring(0, 32) + '...',
                amount: contract.amount,
                signature: signature.substring(0, 32) + '...'
            });

            const txResult = await fetch('http://localhost:2222/txn', {
                method: 'POST', 
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${contractToken}`,
                    'x-auth-token': process.env.NETWORK_SECRET,
                    'x-contract-id': contract.contractId  // Ensure contract ID is in headers
                },
                body: JSON.stringify({
                    from: {
                        publicKey: contract.creator.publicKey,
                        privateKey: contract.creator.privateKey
                    },
                    to: contract.participants[0].publicKey,
                    amount: Number(contract.amount),
                    type: 'CONTRACT_PAYMENT',
                    timestamp: transaction.timestamp,
                    signature: signature,
                    contractId: contract.contractId,  // Include contract ID in body
                    token: contractToken
                })
            });

            // Handle response with error checking
            try {
                const txResponse = await txResult.text();
                const parsedResponse = JSON.parse(txResponse);
                console.log('Transaction response:', parsedResponse);

                if (!txResult.ok) {
                    throw new Error(`Failed to process contract payment: ${parsedResponse.error || 'Unknown error'}`);
                }

                // Update contract state after successful payment
                const payment = {
                    timestamp: Date.now(),
                    amount: contract.amount,
                    status: 'SUCCESS',
                    signature: signature
                };
                
                contract.addPayment(payment);
                contract.nextPaymentDate = new Date(Date.now() + contract.interval);

                return payment;
            } catch (error) {
                console.error('Transaction response error:', error);
                throw error;
            }
        } catch (error) {
            console.error('Contract payment error:', error);
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