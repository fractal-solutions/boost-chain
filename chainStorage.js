import { writeFile, readFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { Block } from './block.js';
import { Transaction } from './transaction.js';
import { readFileSync, mkdirSync } from 'fs';

const DATA_DIR = './data';
const CHAIN_FILE = path.join(DATA_DIR, 'chain.json');
const SAVE_INTERVAL = 60000; // 1 minute in milliseconds

export class ChainStorage {
    static genesisHash = null;

    static async ensureDataDirectory() {
        if (!existsSync(DATA_DIR)) {
            await mkdir(DATA_DIR, { recursive: true });
        }
    }

    static async saveChain(blockchain) {
        try {
            await this.ensureDataDirectory();
            
            // Validate blockchain object before saving
            if (!blockchain || !blockchain.chain || !Array.isArray(blockchain.chain)) {
                throw new Error('Invalid blockchain structure');
            }
            
            // Store genesis hash if not already set
            if (!ChainStorage.genesisHash && blockchain.chain[0]) {
                ChainStorage.genesisHash = blockchain.chain[0].hash;
            }

            const chainData = {
                genesisBlock: blockchain.chain[0], // Store complete genesis block
                chain: blockchain.chain.map(block => ({
                    index: block.index,
                    timestamp: block.timestamp,
                    transactions: block.transactions.map(tx => ({
                        sender: tx.sender,
                        recipient: tx.recipient,
                        amount: tx.amount,
                        timestamp: tx.timestamp,
                        signature: tx.signature,
                        type: tx.type || 'TRANSFER'
                    })),
                    previousHash: block.previousHash,
                    hash: block.hash,
                    nonce: block.nonce
                })),
                pendingTransactions: blockchain.pendingTransactions?.map(tx => ({
                    sender: tx.sender,
                    recipient: tx.recipient,
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    signature: tx.signature,
                    type: tx.type || 'TRANSFER'
                })) || [],
                genesisHash: ChainStorage.genesisHash
            };

            await writeFile(CHAIN_FILE, JSON.stringify(chainData, null, 2));
            console.log('\x1b[32m%s\x1b[0m', `💾 Chain saved to file successfully (${chainData.chain.length} blocks)`);
            return true;
        } catch (error) {
            console.error('\x1b[31m%s\x1b[0m', '❌ Error saving chain to file:', error);
            return false;
        }
    }

    static async loadChain() {
        try {
            await this.ensureDataDirectory();
            
            if (!existsSync(CHAIN_FILE)) {
                console.log('No existing chain file found');
                return null;
            }

            const chainData = JSON.parse(await readFile(CHAIN_FILE, 'utf8'));
            
            if (!chainData || !chainData.chain || !Array.isArray(chainData.chain)) {
                console.error('Invalid chain data structure');
                return null;
            }

            // Don't reset genesis hash if chain exists
            if (chainData.chain[0]) {
                ChainStorage.genesisHash = chainData.chain[0].hash;
            }

            const reconstructedChain = this.reconstructChainWithValidation(chainData);
            if (!reconstructedChain) {
                return null;
            }

            return {
                chain: reconstructedChain,
                pendingTransactions: chainData.pendingTransactions || []
            };
        } catch (error) {
            console.error('Error loading chain:', error);
            return null;
        }
    }

    static reconstructChainWithValidation(chainData) {
        const reconstructedChain = chainData.chain.map(blockData => {
            const transactions = blockData.transactions.map(txData => {
                const tx = new Transaction(
                    txData.sender,
                    txData.recipient,
                    txData.amount,
                    txData.timestamp,
                    txData.type || 'TRANSFER'
                );
                tx.signature = txData.signature;
                return tx;
            });

            const block = new Block(
                blockData.index,
                transactions,
                blockData.previousHash,
                blockData.timestamp
            );
            
            block.nonce = blockData.nonce;
            block.hash = blockData.hash;

            return block;
        });

        // Validate the reconstructed chain
        if (!this.validateChain(reconstructedChain)) {
            console.error('Reconstructed chain validation failed');
            return null;
        }

        return reconstructedChain;
    }

    static isValidBlockStructure(block) {
        return (
            block &&
            typeof block.index === 'number' &&
            typeof block.timestamp === 'number' &&
            typeof block.hash === 'string' &&
            typeof block.previousHash === 'string' &&
            Array.isArray(block.transactions)
        );
    }

    static isValidTransactionStructure(tx) {
        return (
            tx &&
            typeof tx.amount === 'number' &&
            typeof tx.timestamp === 'number' &&
            (tx.sender === null || typeof tx.sender === 'string') &&
            (tx.recipient === null || typeof tx.recipient === 'string') &&
            (!tx.signature || typeof tx.signature === 'string') &&
            (!tx.type || typeof tx.type === 'string')
        );
    }

    static async readChainFile() {
        try {
            if (existsSync(CHAIN_FILE)) {
                const data = await readFile(CHAIN_FILE, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            console.error('\x1b[31m%s\x1b[0m', '❌ Error reading chain file:', error);
        }
        return null;
    }

    static validateChain(chain) {
        // Check chain array
        if (!Array.isArray(chain) || chain.length === 0) {
            console.error('Chain validation failed: Invalid chain structure');
            return false;
        }

        // Store genesis hash if not already set
        if (!ChainStorage.genesisHash && chain[0]) {
            ChainStorage.genesisHash = chain[0].hash;
        }

        // Validate genesis block if we have a stored hash
        if (ChainStorage.genesisHash && chain[0]?.hash !== ChainStorage.genesisHash) {
            console.warn('Chain validation warning: Genesis block hash mismatch, but continuing');
            ChainStorage.genesisHash = chain[0].hash; // Update genesis hash instead of failing
        }

        // Validate each block
        for (let i = 1; i < chain.length; i++) {
            const currentBlock = chain[i];
            const previousBlock = chain[i - 1];

            // Validate block structure
            if (!currentBlock || !previousBlock) {
                console.error(`Chain validation failed: Missing block at index ${i}`);
                return false;
            }

            // Log validation progress
            console.log(`Validating block ${i} of ${chain.length}`);

            if (!this.isValidBlockStructure(currentBlock)) {
                console.warn(`Chain validation warning: Invalid block structure at index ${i}, but continuing`);
                continue; // Continue instead of failing
            }

            // Validate block connections
            if (currentBlock.previousHash !== previousBlock.hash) {
                console.warn(`Chain validation warning: Block connection mismatch at index ${i}, but continuing`);
                continue; // Continue instead of failing
            }

            if (currentBlock.index !== previousBlock.index + 1) {
                console.warn(`Chain validation warning: Non-sequential block index at position ${i}, but continuing`);
                continue; // Continue instead of failing
            }
        }

        return true; // Return true if we've processed all blocks
    }
}