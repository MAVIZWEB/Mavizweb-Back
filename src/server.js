require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('rate-limiter-flexible').RateLimiterMemory;
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Web3 = require('web3');
const Flutterwave = require('flutterwave-node-v3');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || "https://maviz-kefi.onrender.com",
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const rateLimiter = new rateLimit({
  points: parseInt(process.env.API_RATE_LIMIT) || 100,
  duration: 3600 // 1 hour
});

app.use((req, res, next) => {
  rateLimiter.consume(req.ip)
    .then(() => next())
    .catch(() => res.status(429).json({ error: 'Too many requests' }));
});

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Web3 setup
const web3 = new Web3(process.env.BNB_RPC_URL);
const MVZX_CONTRACT_ABI = [/* Your MVZX Token ABI here */];
const USDT_CONTRACT_ABI = [/* Your USDT Token ABI here */];

const mvzxContract = new web3.eth.Contract(MVZX_CONTRACT_ABI, process.env.MVZX_TOKEN_CONTRACT);
const usdtContract = new web3.eth.Contract(USDT_CONTRACT_ABI, process.env.USDT_CONTRACT);

// Flutterwave setup
const flw = new Flutterwave(process.env.FLW_PUBLIC_KEY, process.env.FLW_SECRET_KEY);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// User registration
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, pin, referralCode } = req.body;

    // Validate input
    if (!email || !pin || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'Valid email and 4-digit PIN required' });
    }

    // Check if user exists
    const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash PIN with salt
    const saltRounds = 10;
    const hashedPin = await bcrypt.hash(pin + process.env.PIN_SALT, saltRounds);

    // Generate wallet address
    const account = web3.eth.accounts.create();
    const walletAddress = account.address;
    const encryptedPrivateKey = await bcrypt.hash(account.privateKey, saltRounds);

    // Create user in database
    const result = await pool.query(
      `INSERT INTO users (email, pin_hash, wallet_address, private_key_encrypted, referral_code) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id, email, wallet_address, created_at`,
      [email, hashedPin, walletAddress, encryptedPrivateKey, referralCode || null]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email, wallet: user.wallet_address },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        walletAddress: user.wallet_address,
        createdAt: user.created_at
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, pin } = req.body;

    if (!email || !pin) {
      return res.status(400).json({ error: 'Email and PIN required' });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, email, pin_hash, wallet_address FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify PIN
    const isValidPin = await bcrypt.compare(pin + process.env.PIN_SALT, user.pin_hash);
    if (!isValidPin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email, wallet: user.wallet_address },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        walletAddress: user.wallet_address
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user wallet balance
app.get('/api/wallet/balance', authenticateToken, async (req, res) => {
  try {
    const walletAddress = req.user.wallet;

    // Get MVZX balance
    const mvzxBalance = await mvzxContract.methods.balanceOf(walletAddress).call();
    const formattedMvzx = web3.utils.fromWei(mvzxBalance, 'ether');

    // Get USDT balance
    const usdtBalance = await usdtContract.methods.balanceOf(walletAddress).call();
    const formattedUsdt = web3.utils.fromWei(usdtBalance, 'ether');

    res.json({
      mvzx: parseFloat(formattedMvzx),
      usdt: parseFloat(formattedUsdt),
      walletAddress
    });

  } catch (error) {
    console.error('Balance check error:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

// Initiate Flutterwave payment
app.post('/api/payment/flutterwave', authenticateToken, async (req, res) => {
  try {
    const { amount, currency = 'NGN' } = req.body;
    const userEmail = req.user.email;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount required' });
    }

    const paymentData = {
      tx_ref: 'MVZX-' + Date.now(),
      amount: amount,
      currency: currency,
      redirect_url: process.env.FRONTEND_URL + '/payment-success',
      customer: {
        email: userEmail,
      },
      customizations: {
        title: 'MAVIZ SWAPS',
        description: 'MVZX Token Purchase',
        logo: 'https://i.imgur.com/VbxvCK6.jpeg'
      }
    };

    const response = await flw.Payment.initialize(paymentData);
    
    if (response.status === 'success') {
      res.json({
        paymentUrl: response.data.link,
        transactionRef: paymentData.tx_ref
      });
    } else {
      res.status(400).json({ error: 'Payment initiation failed' });
    }

  } catch (error) {
    console.error('Flutterwave error:', error);
    res.status(500).json({ error: 'Payment processing failed' });
  }
});

// Spin game endpoint
app.post('/api/game/spin', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const cost = 5; // 5 MVZX per spin

    // Check user balance
    const walletAddress = req.user.wallet;
    const balance = await mvzxContract.methods.balanceOf(walletAddress).call();
    const userBalance = parseFloat(web3.utils.fromWei(balance, 'ether'));

    if (userBalance < cost) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Deduct spin cost
    const transferTx = await mvzxContract.methods.transfer(
      process.env.COMPANY_WALLET,
      web3.utils.toWei(cost.toString(), 'ether')
    ).send({ from: walletAddress });

    // Determine prize (simplified logic)
    const prizes = [0, 0.125, 0.25, 0.5, 0.75, 1, 2, 3];
    const prizeIndex = Math.floor(Math.random() * prizes.length);
    const prizeAmount = prizes[prizeIndex];

    let resultMessage = 'Try again!';
    if (prizeAmount > 0) {
      // Award prize
      await mvzxContract.methods.transfer(
        walletAddress,
        web3.utils.toWei(prizeAmount.toString(), 'ether')
      ).send({ from: process.env.COMPANY_WALLET });

      resultMessage = `Congratulations! You won ${prizeAmount} MVZX!`;
    }

    // Record spin in database
    await pool.query(
      `INSERT INTO game_spins (user_id, cost, prize_amount, result) 
       VALUES ($1, $2, $3, $4)`,
      [userId, cost, prizeAmount, resultMessage]
    );

    res.json({
      success: true,
      prize: prizeAmount,
      message: resultMessage,
      transactionHash: transferTx.transactionHash
    });

  } catch (error) {
    console.error('Spin game error:', error);
    res.status(500).json({ error: 'Spin game failed' });
  }
});

// Withdrawal endpoint
app.post('/api/wallet/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, address, network, pin } = req.body;
    const userId = req.user.userId;
    const walletAddress = req.user.wallet;

    // Verify PIN
    const userResult = await pool.query('SELECT pin_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isValidPin = await bcrypt.compare(pin + process.env.PIN_SALT, userResult.rows[0].pin_hash);
    if (!isValidPin) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // Validate withdrawal amount
    const fee = 5; // 5 MVZX withdrawal fee
    const totalAmount = parseFloat(amount) + fee;

    if (totalAmount < 50) {
      return res.status(400).json({ error: 'Minimum withdrawal is 50 MVZX' });
    }

    // Check balance
    const balance = await mvzxContract.methods.balanceOf(walletAddress).call();
    const userBalance = parseFloat(web3.utils.fromWei(balance, 'ether'));

    if (userBalance < totalAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Process withdrawal
    const withdrawalTx = await mvzxContract.methods.transfer(
      address,
      web3.utils.toWei(amount.toString(), 'ether')
    ).send({ from: walletAddress });

    // Transfer fee to company wallet
    await mvzxContract.methods.transfer(
      process.env.COMPANY_WALLET,
      web3.utils.toWei(fee.toString(), 'ether')
    ).send({ from: walletAddress });

    // Record transaction
    await pool.query(
      `INSERT INTO transactions (user_id, type, amount, fee, address, network, status, tx_hash) 
       VALUES ($1, 'withdrawal', $2, $3, $4, $5, 'pending', $6)`,
      [userId, amount, fee, address, network, withdrawalTx.transactionHash]
    );

    res.json({
      success: true,
      message: 'Withdrawal processing',
      transactionHash: withdrawalTx.transactionHash,
      amount: amount,
      fee: fee
    });

  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
});

// Get user transactions
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const result = await pool.query(
      `SELECT id, type, amount, fee, address, network, status, tx_hash, created_at 
       FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`,
      [userId]
    );

    res.json({ transactions: result.rows });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`MAVIZ backend server running on port ${PORT}`);
});

module.exports = app￼Enter
