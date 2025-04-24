import { createHash } from "crypto";
import jwt from "jsonwebtoken";

export class SmartContract {
    constructor(options) {
        this.contractId = createHash('sha256')
            .update(Date.now().toString() + JSON.stringify(options))
            .digest('hex');
        
        // Store complete creator object
        this.creator = {
            publicKey: options.creator.publicKey,
            privateKey: options.creator.privateKey,
            type: options.creator.type
        };

        this.authInfo = {
            publicKey: options.creator.publicKey,
            privateKey: options.creator.privateKey,
            // Don't store the short-lived JWT
        };

        // Store complete participant objects
        this.participants = options.participants.map(p => ({
            publicKey: p.publicKey || p,
            type: p.type || 'USER'
        }));

        this.amount = options.amount;
        this.interval = options.interval; // in milliseconds
        this.startDate = options.startDate || Date.now();
        this.endDate = options.endDate;
        this.status = 'ACTIVE'; // ACTIVE, COMPLETED, TERMINATED
        this.terms = options.terms || {};
        this.paymentHistory = [];
        const firstPaymentDate = new Date(this.startDate + this.interval);
        this.nextPaymentDate = firstPaymentDate//firstPaymentDate.toISOString();
        this.type = options.type || 'RECURRING_PAYMENT'; // Can be expanded for different contract types
        this.metadata = options.metadata || {};

        // Add new fields
        this.lastProcessedPayment = null;
        this.failedPayments = [];
        this.totalPaid = 0;
        this.remainingBalance = options.totalAmount || options.amount * 
            (options.endDate ? Math.ceil((options.endDate - options.startDate) / options.interval) : Infinity);

        if (!options.creator.privateKey) {
            throw new Error('Private key required for recurring payments');
        }

        this.serviceAuth = {
            contractId: this.contractId,
            type: 'SERVICE_TOKEN',
            permissions: ['execute_contract_payment']
        };

        // Create permanent contract token
        this.contractToken = jwt.sign(
            this.serviceAuth,
            process.env.NETWORK_SECRET,
            { expiresIn: '10y' } // Long-lived token for contract
        );
    }

    addPayment(payment) {
        this.paymentHistory.push({
            ...payment,
            timestamp: Date.now(),
            status: payment.status || 'COMPLETED'
        });

        if (payment.status === 'SUCCESS') {
            this.totalPaid += payment.amount;
            this.remainingBalance -= payment.amount;
            this.lastProcessedPayment = Date.now();
        } else {
            this.failedPayments.push({
                timestamp: Date.now(),
                amount: payment.amount,
                error: payment.error
            });
        }

        this.updateNextPaymentDate();
    }

    updateNextPaymentDate() {
        // Convert current date to milliseconds and add interval
        const nextDate = new Date(Date.now() + this.interval);
        this.nextPaymentDate = nextDate.toISOString();
    }

    getStatus() {
        return {
            contractId: this.contractId,
            status: this.status,
            nextPaymentDate: this.nextPaymentDate,
            paymentHistory: this.paymentHistory,
            remainingPayments: this.calculateRemainingPayments()
        };
    }

    calculateRemainingPayments() {
        if (this.endDate) {
            return Math.ceil((this.endDate - Date.now()) / this.interval);
        }
        return Infinity;
    }

    terminate() {
        this.status = 'TERMINATED';
        return {
            contractId: this.contractId,
            terminationDate: Date.now(),
            status: this.status
        };
    }

    getDetailedStatus() {
        return {
            ...this.getStatus(),
            totalPaid: this.totalPaid,
            remainingBalance: this.remainingBalance,
            failedPayments: this.failedPayments,
            lastProcessedPayment: this.lastProcessedPayment
        };
    }
}