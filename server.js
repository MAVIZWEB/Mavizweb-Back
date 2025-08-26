 // Add this to your existing server.js file - AUTH SECTION

// User registration
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, pin, referralCode } = req.body;

    // Validate input
    if (!email || !pin || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ 
        success: false,
        error: 'Valid email and 4-digit PIN required' 
      });
    }

    // Check if user exists
    const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(409).json({ 
        success: false,
        error: 'User already exists' 
      });
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

    // Return proper JSON response
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        walletAddress: user.wallet_address,
        createdAt: user.created_at
      },
      walletAddress: user.wallet_address
    });

  } catch (error) {
    console.error('Signup error:', error);
    // Return proper JSON error response
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, pin } = req.body;

    if (!email || !pin) {
      return res.status(400).json({ 
        success: false,
        error: 'Email and PIN required' 
      });
    }

    // Find user
    const result = await pool.query(
      'SELECT id, email, pin_hash, wallet_address FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    const user = result.rows[0];

    // Verify PIN
    const isValidPin = await bcrypt.compare(pin + process.env.PIN_SALT, user.pin_hash);
    if (!isValidPin) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid credentials' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email, wallet: user.wallet_address },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Return proper JSON response
    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        walletAddress: user.wallet_address
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    // Return proper JSON error response
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'MAVIZ Backend API'
  });
});

// Test endpoint to check if server is working
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true,
    message: 'Server is working!',
    timestamp: new Date().toISOString()
  });
});
