-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    pin_hash VARCHAR(255) NOT NULL,
    wallet_address VARCHAR(255) UNIQUE NOT NULL,
    private_key_encrypted VARCHAR(255) NOT NULL,
    referral_code VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    type VARCHAR(50) NOT NULL, -- 'deposit', 'withdrawal', 'transfer'
    amount DECIMAL(18, 8) NOT NULL,
    fee DECIMAL(18, 8) DEFAULT 0,
    address VARCHAR(255),
    network VARCHAR(50),
    status VARCHAR(50) DEFAULT 'pending',
    tx_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Game spins table
CREATE TABLE game_spins (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    cost DECIMAL(18, 8) NOT NULL,
    prize_amount DECIMAL(18, 8) NOT NULL,
    result VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Referrals table
CREATE TABLE referrals (
    id SERIAL PRIMARY KEY,
    referrer_id INTEGER REFERENCES users(id),
    referred_id INTEGER REFERENCES users(id) UNIQUE,
    reward_amount DECIMAL(18, 8) DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_wallet ON users(wallet_address);
CREATE INDEX idx_transactions_user ON transactions(user_id);
CREATE INDEX idx_transactions_tx_hash ON transactions(tx_hash);
CREATE INDEX idx_game_spins_user ON game_spins(user_id);
CREATE INDEX idx_referrals_referrer ON referrals(referrer_id);
CREATE INDEX idx_referrals_referred ON referrals(referred_id);
