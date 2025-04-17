import { createHash, createCipheriv, createDecipheriv, randomBytes } from "crypto";
import jwt from "jsonwebtoken";
import { JWT_SECRET, ENCRYPTION_KEY } from './config.js';

class UserManager {
    constructor() {
        this.users = new Map();
        this.phoneNumberIndex = new Map();
        this.usernameIndex = new Map();
        this.verificationCodes = new Map();
        this.verificationAttempts = new Map();
    }

    encryptPrivateKey(privateKey, password) {
        try {
            // Generate a 32-byte key from the password
            const key = createHash('sha256')
                .update(ENCRYPTION_KEY)
                .digest('hex')
                .slice(0, 32);
            
            const iv = randomBytes(16);
            const cipher = createCipheriv('aes-256-cbc', Buffer.from(key), iv);
            
            const encryptedKey = Buffer.concat([
                cipher.update(privateKey),
                cipher.final()
            ]);
            
            return {
                iv: iv.toString('hex'),
                encryptedKey: encryptedKey.toString('hex')
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt private key');
        }
    }

    decryptPrivateKey(encryptedData, password) {
        try {
            // Generate the same 32-byte key from the password
            const key = createHash('sha256')
                .update(ENCRYPTION_KEY)
                .digest('hex')
                .slice(0, 32);
            
            const decipher = createDecipheriv(
                'aes-256-cbc',
                Buffer.from(key),
                Buffer.from(encryptedData.iv, 'hex')
            );
            
            const decryptedKey = Buffer.concat([
                decipher.update(Buffer.from(encryptedData.encryptedKey, 'hex')),
                decipher.final()
            ]);
            
            return decryptedKey.toString();
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt private key');
        }
    }

    async sendVerificationSMS(phoneNumber) {
        // Generate 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store code with expiration (5 minutes)
        this.verificationCodes.set(phoneNumber, {
            code,
            expires: Date.now() + 5 * 60 * 1000,
            attempts: 0
        });

        try {
            // Here I'll integrate with an SMS service like Twilio
            // For demonstration, we'll just log the code
            console.log(`Verification code for ${phoneNumber}: ${code}`);
            
            return true;
        } catch (error) {
            console.error('SMS sending error:', error);
            return false;
        }
    }

    verifyPhone(phoneNumber, code) {
        const verification = this.verificationCodes.get(phoneNumber);
        
        if (!verification) {
            throw new Error('No verification code found. Request a new one.');
        }

        if (Date.now() > verification.expires) {
            this.verificationCodes.delete(phoneNumber);
            throw new Error('Verification code expired');
        }

        verification.attempts++;
        
        if (verification.attempts > 3) {
            this.verificationCodes.delete(phoneNumber);
            throw new Error('Too many attempts. Request a new code.');
        }

        if (verification.code !== code) {
            throw new Error('Invalid verification code');
        }

        // Clear verification data after successful verification
        this.verificationCodes.delete(phoneNumber);
        return true;
    }

    async createUser(userData) {
        try {
            // Validate required fields
            if (!userData.phoneNumber || !userData.username || !userData.password) {
                throw new Error('Phone number, username and password are required');
            }

            // Basic validation
            if (!/^\+\d{10,15}$/.test(userData.phoneNumber)) {
                throw new Error('Invalid phone number format. Use +XXX format');
            }
            if (userData.username.length < 3) {
                throw new Error('Username must be at least 3 characters long');
            }
            if (userData.password.length < 8) {
                throw new Error('Password must be at least 8 characters long');
            }

            if (!userData.isPhoneVerified) {
                throw new Error('Phone number must be verified before registration');
            }

            // Check existing users
            if (this.phoneNumberIndex.has(userData.phoneNumber)) {
                throw new Error('Phone number already registered');
            }
            if (this.usernameIndex.has(userData.username)) {
                throw new Error('Username already taken');
            }

            // Generate blockchain keys using boost-chain's /newuser endpoint
            const response = await fetch('http://localhost:2222/newuser');
            if (!response.ok) {
                throw new Error('Failed to generate blockchain keys');
            }

            const { user: keys } = await response.json();

            // Encrypt private key with user's password
            const encryptedPrivateKey = this.encryptPrivateKey(keys.privateKey, userData.password);

            // Create user object
            const user = {
                id: createHash('sha256').update(Date.now().toString()).digest('hex'),
                username: userData.username,
                phoneNumber: userData.phoneNumber,
                publicKey: keys.publicKey,
                encryptedPrivateKey: encryptedPrivateKey,
                role: userData.role || 'USER',
                createdAt: Date.now(),
                status: 'ACTIVE'
            };

            // Store user
            this.users.set(user.id, user);
            this.phoneNumberIndex.set(user.phoneNumber, user.id);
            this.usernameIndex.set(user.username, user.id);

            // Generate JWT token
            const token = this.generateToken(user);

            // Return user data (including private key only during creation)
            return {
                success: true,
                message: 'User created successfully',
                data: {
                    id: user.id,
                    username: user.username,
                    phoneNumber: user.phoneNumber,
                    publicKey: user.publicKey,
                    privateKey: keys.privateKey, // Only sent once during creation
                    token
                }
            };
        } catch (error) {
            console.error('User creation error:', error);
            throw error;
        }
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

    async authenticateUser(phoneNumber, password) {
        const userId = this.phoneNumberIndex.get(phoneNumber);
        if (!userId) {
            throw new Error('User not found');
        }

        const user = this.users.get(userId);
        
        try {
            // Attempt to decrypt private key as authentication
            this.decryptPrivateKey(user.encryptedPrivateKey, password);
            
            // Generate new token
            const token = this.generateToken(user);
            
            return {
                success: true,
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    phoneNumber: user.phoneNumber,
                    publicKey: user.publicKey
                }
            };
        } catch (error) {
            throw new Error('Invalid credentials');
        }
    }

    getUserByUsername(username) {
        const userId = this.usernameIndex.get(username);
        if (!userId) {
            throw new Error('User not found');
        }
        const user = this.users.get(userId);
        return {
            username: user.username,
            publicKey: user.publicKey
        };
    }

    getUserByPhone(phoneNumber) {
        const userId = this.phoneNumberIndex.get(phoneNumber);
        if (!userId) {
            throw new Error('User not found');
        }
        const user = this.users.get(userId);
        return {
            phoneNumber: user.phoneNumber,
            publicKey: user.publicKey
        };
    }
}

const corsHeaders = {
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };

// Initialize user manager
const userManager = new UserManager();

// Start user management server
console.log('Starting USER Management Server on 2225...');
  Bun.serve({
    port: 2225,
    routes: {
      '/register': {
        POST: async (req) => {
          try {
            const userData = await req.json();
            const result = await userManager.createUser(userData);
            return Response.json(result, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false, 
              error: error.message
            }, { 
              status: 400,
              headers: corsHeaders 
            });
          }
        },
      },
  
      '/login': {
        POST: async (req) => {
          try {
            const { phoneNumber, password } = await req.json();
            const result = await userManager.authenticateUser(phoneNumber, password);
            return Response.json(result, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 401,
              headers: corsHeaders 
            });
          }
        },
      },
  
      '/verify': {
        POST: async (req) => {
          try {
            const { token } = await req.json();
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
              throw new Error('Invalid token');
            }
            return Response.json({
              success: true,
              user: decoded
            }, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 401,
              headers: corsHeaders 
            });
          }
        },
      },
  
      '/confirm-phone': {
        POST: async (req) => {
          try {
            const { phoneNumber, code } = await req.json();
            const verified = userManager.verifyPhone(phoneNumber, code);
            return Response.json({
              success: true,
              verified
            }, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 400,
              headers: corsHeaders 
            });
          }
        },
      },
  
      '/verify-phone': {
        POST: async (req) => {
          try {
            const { phoneNumber } = await req.json();
            const sent = await userManager.sendVerificationSMS(phoneNumber);
            return Response.json({
              success: sent,
              message: sent ? 'Verification code sent' : 'Failed to send code'
            }, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 400,
              headers: corsHeaders 
            });
          }
        },
      },

      '/user/by-username': {
        POST: async (req) => {
          try {
            const { username } = await req.json();
            const user = userManager.getUserByUsername(username);
            return Response.json({
              success: true,
              data: user
            }, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 404,
              headers: corsHeaders 
            });
          }
        }
      },

      '/user/by-phone': {
        POST: async (req) => {
          try {
            const { phoneNumber } = await req.json();
            const user = userManager.getUserByPhone(phoneNumber);
            return Response.json({
              success: true,
              data: user
            }, { headers: corsHeaders });
          } catch (error) {
            return Response.json({
              success: false,
              error: error.message
            }, { 
              status: 404,
              headers: corsHeaders 
            });
          }
        }
      }
    },
  
    // Global fetch handler for OPTIONS requests
    fetch(req) {
      if (req.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: corsHeaders
        });
      }
    }
  });


// curl -X POST http://localhost:2225/register \
// -H "Content-Type: application/json" \
// -d '{
//     "username": "alice",
//     "phoneNumber": "+1234567890",
//     "password": "securepassword123",
//     "isPhoneVerified": true
// }'

// curl -X POST http://localhost:2225/login \
// -H "Content-Type: application/json" \
// -d '{
//     "phoneNumber": "+1234567890",
//     "password": "securepassword123"
// }'

// curl -X POST http://localhost:2225/verify \
// -H "Content-Type: application/json" \
// -d '{
//     "token": "your-jwt-token"
// }'

// Request phone verification
// curl -X POST http://localhost:2225/verify-phone \
// -H "Content-Type: application/json" \
// -d '{"phoneNumber": "+1234567890"}'

// Confirm phone verification
// curl -X POST http://localhost:2225/confirm-phone \
// -H "Content-Type: application/json" \
// -d '{
//     "phoneNumber": "+1234567890",
//     "code": "123456"
// }'