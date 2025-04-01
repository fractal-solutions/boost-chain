//SMART CONTRACT SERVER
import { SmartContractManager } from "./smartContractManager.js";
import { SmartContract } from "./smartContract.js";
process.env.NETWORK_SECRET = 'test-secret-123';
// Initialize contract manager
const contractManager = new SmartContractManager();

// Contract API Server
console.log('Starting SMART CONTRACT Server on 2223...')
Bun.serve({
    port: 2223, // Different port from main blockchain server
    routes: {
        '/contract': {
            // Create new smart contract
            POST: async (req) => {
                try {
                    const data = await req.json();
                    // Validate required fields
                    const requiredFields = ['creator', 'participants', 'amount', 'interval', 'endDate'];
                    for (const field of requiredFields) {
                        if (!data[field]) {
                            throw new Error(`Missing required field: ${field}`);
                        }
                    }

                    const contract = contractManager.createContract({
                        ...data,
                        startDate: Date.now(),//data.startDate || Date.now(),
                        status: 'ACTIVE'
                    });

                    // Create initial transaction via main blockchain API
                    const txResult = await fetch('http://localhost:2222/txn', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'x-auth-token': process.env.NETWORK_SECRET
                        },
                        body: JSON.stringify({
                            from: contract.creator,
                            to: contract.participants[0],
                            amount: contract.amount,
                            type: 'CONTRACT_PAYMENT'
                        })
                    });

                    if (!txResult.ok) {
                        throw new Error('Failed to process initial contract payment');
                    }

                    return Response.json({
                        success: true,
                        contractId: contract.contractId,
                        nextPaymentDate: contract.nextPaymentDate
                    });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { status: 400 });
                }
            }
        },

        /*curl -X POST http://localhost:2223/contract \
        -H "Content-Type: application/json" \
        -d '{
            "creator": "alice_public_key",
            "participants": ["bob_public_key"],
            "amount": 100,
            "interval": 604800000,
            "startDate": "2024-03-26T00:00:00.000Z",
            "endDate": "2024-06-26T00:00:00.000Z",
            "terms": {
                "paymentMethod": "BOOST",
                "penalties": {
                    "lateFee": 10
                }
            }
        }' */

        '/contract/:id': {
            // Get contract details
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { status: 404 });
                }
                return Response.json(contract);
            },

            // Terminate contract
            DELETE: async (req) => {
                try {
                    const id = req.params.id;
                    const result = contractManager.terminateContract(id);
                    return Response.json({
                        success: true,
                        terminationDetails: result
                    });
                } catch (error) {
                    return Response.json({
                        success: false,
                        error: error.message
                    }, { status: 400 });
                }
            }
        },

        '/contract/:id/payments': {
            // Get payment history
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { status: 404 });
                }
                return Response.json(contract.paymentHistory);
            }
        },

        /* curl http://localhost:2223/contract/[contract_id]/payments */

        '/contracts/user/:address': {
            // Get user's contracts
            GET: async (req) => {
                const address = req.params.address;
                const contracts = contractManager.getContractsByParticipant(address);
                return Response.json({ contracts });
            }
        },

        '/contract/:id/status': {
            // Get contract status
            GET: async (req) => {
                const id = req.params.id;
                const contract = contractManager.getContract(id);
                if (!contract) {
                    return Response.json({
                        error: 'Contract not found'
                    }, { status: 404 });
                }
                return Response.json(contract.getStatus());
            }
        }
        /*curl http://localhost:2223/contract/[contract_id]/status */
    }
});

// Batch process payments
async function processBatchPayments(contracts) {
    const batchSize = 5;
    for (let i = 0; i < contracts.length; i += batchSize) {
        const batch = contracts.slice(i, i + batchSize);
        await Promise.all(batch.map(contract => 
            contractManager.executeScheduledPayment(contract)
        ));
    }
}

setInterval(async () => {
    const contracts = contractManager.getAllContracts();
    const batchContracts = contracts
        .filter(c => c.status === 'ACTIVE' && 
                Date.now() >= new Date(c.nextPaymentDate).getTime());
    console.log('Checking for scheduled payments...');
    console.log('Contracts:', contracts.map(contract => ({
                    contractId: contract.contractId,
                    creator: contract.creator.publicKey,
                    participants: contract.participants.map(p => p.publicKey),
                    amount: contract.amount,
                    status: contract.status,
                    nextPaymentDate: contract.nextPaymentDate,
                    endDate: contract.endDate,
    })));
    await processBatchPayments(batchContracts);
}, 10000);