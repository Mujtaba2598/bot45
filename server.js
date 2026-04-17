const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// Ensure data directories exist
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);

// Users file
const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}

// Pending users file
if (!fs.existsSync(pendingFile)) {
    fs.writeFileSync(pendingFile, JSON.stringify({}));
}

function readUsers() {
    return JSON.parse(fs.readFileSync(usersFile));
}
function writeUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}
function readPending() {
    return JSON.parse(fs.readFileSync(pendingFile));
}
function writePending(pending) {
    fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2));
}

// Helper: encrypt/decrypt API keys
function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTHENTICATION WITH APPROVAL ====================

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    const users = readUsers();
    if (users[email]) {
        return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const pending = readPending();
    if (pending[email]) {
        return res.status(400).json({ success: false, message: 'Registration request already pending. Wait for owner approval.' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = {
        email,
        password: hashedPassword,
        requestedAt: new Date().toISOString(),
        status: 'pending'
    };
    writePending(pending);
    
    res.json({ 
        success: true, 
        message: 'Registration request sent to owner. You will be notified when approved.' 
    });
});

app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const pending = readPending();
    const pendingList = Object.keys(pending).map(email => ({
        email: email,
        requestedAt: pending[email].requestedAt,
        status: pending[email].status
    }));
    res.json({ success: true, pending: pendingList });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    
    const pending = readPending();
    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'No pending request from this user' });
    }
    
    const users = readUsers();
    users[email] = {
        email: email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        apiKey: "",
        secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} has been approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email required' });
    
    const pending = readPending();
    if (!pending[email]) {
        return res.status(404).json({ success: false, message: 'No pending request from this user' });
    }
    
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} has been rejected.` });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) {
        const pending = readPending();
        if (pending[email]) {
            return res.status(401).json({ success: false, message: 'Your registration is pending owner approval.' });
        }
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isApproved && !user.isOwner) {
        return res.status(401).json({ success: false, message: 'Your account is not approved yet. Contact owner.' });
    }
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false, email: user.email });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token provided' });
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== API KEY MANAGEMENT WITH FIXED SIGNATURE ====================

// ENHANCED TIME SYNC - Gets accurate server time offset
async function getServerTimeOffset() {
    try {
        const startTime = Date.now();
        const response = await axios.get('https://api.binance.com/api/v3/time', { timeout: 5000 });
        const endTime = Date.now();
        const serverTime = response.data.serverTime;
        const localTime = (startTime + endTime) / 2;
        const offset = serverTime - localTime;
        console.log(`⏰ Time sync: Local offset = ${Math.round(offset)}ms`);
        return offset;
    } catch (error) {
        console.error("⚠️ Could not sync time, using local clock");
        return 0;
    }
}

// FIXED SIGNATURE GENERATION with percent-encoding (Binance requirement)
function generateSignature(queryString, secret) {
    // PERCENT-ENCODE the payload BEFORE signing (critical fix for Jan 15, 2026 requirement)
    const encodedPayload = encodeURIComponent(queryString);
    return crypto
        .createHmac('sha256', secret)
        .update(encodedPayload)
        .digest('hex');
}

// Verify Binance API keys with proper signature
async function verifyBinanceKeys(apiKey, secretKey) {
    try {
        // Get server time offset
        const timeOffset = await getServerTimeOffset();
        const timestamp = Date.now() + timeOffset;
        
        // Build query string (alphabetical order, recvWindow first)
        const queryString = `recvWindow=5000&timestamp=${timestamp}`;
        
        // Generate signature using percent-encoded query string
        const signature = generateSignature(queryString, secretKey);
        
        const url = `https://api.binance.com/api/v3/account?${queryString}&signature=${signature}`;
        
        const response = await axios({
            method: 'GET',
            url: url,
            headers: { 'X-MBX-APIKEY': apiKey },
            timeout: 10000
        });
        
        // Check if account has trading permission
        if (!response.data.canTrade) {
            return { success: false, error: 'permission' };
        }
        return { success: true };
    } catch (error) {
        const status = error.response?.status;
        const data = error.response?.data;
        console.error('Binance verification error:', data);
        
        if (status === 401 || data?.code === -2015) {
            if (data?.msg && data.msg.includes('IP')) return { success: false, error: 'ip' };
            return { success: false, error: 'permission' };
        }
        if (data?.code === -1021) return { success: false, error: 'timestamp' };
        if (data?.code === -1022) return { success: false, error: 'signature' };
        return { success: false, error: data?.msg || error.message };
    }
}

app.post('/api/set-api-keys', authenticate, async (req, res) => {
    const { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) {
        return res.status(400).json({ success: false, message: 'API key and secret key required' });
    }
    
    // Clean the keys (remove spaces, line breaks)
    const cleanApiKey = apiKey.trim().replace(/[\n\r]/g, '');
    const cleanSecretKey = secretKey.trim().replace(/[\n\r]/g, '');
    
    try {
        const verification = await verifyBinanceKeys(cleanApiKey, cleanSecretKey);
        if (!verification.success) {
            let errorMsg = 'Invalid Binance API keys. ';
            if (verification.error === 'permission') errorMsg += 'Enable "Spot & Margin Trading" in Binance API settings.';
            else if (verification.error === 'ip') errorMsg += 'IP not whitelisted. Set IP restrictions to Unrestricted for testing.';
            else if (verification.error === 'timestamp') errorMsg += 'Server time sync issue. Please try again.';
            else if (verification.error === 'signature') errorMsg += 'Signature error. Check that your Secret Key is correct (no missing characters).';
            else errorMsg += verification.error;
            return res.status(401).json({ success: false, message: errorMsg });
        }
        
        const users = readUsers();
        if (!users[req.user.email]) return res.status(404).json({ success: false, message: 'User not found' });
        
        users[req.user.email].apiKey = encrypt(cleanApiKey);
        users[req.user.email].secretKey = encrypt(cleanSecretKey);
        writeUsers(users);
        
        res.json({ success: true, message: 'API keys saved and verified!' });
    } catch (err) {
        console.error('Key verification error:', err);
        res.status(500).json({ success: false, message: 'Verification failed: ' + err.message });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) {
        return res.json({ success: false, message: 'No API keys set' });
    }
    res.json({
        success: true,
        apiKey: decrypt(user.apiKey),
        secretKey: decrypt(user.secretKey)
    });
});

// ==================== AI TRADING ENGINE ====================
const winStreaks = {};

class AITradingEngine {
    analyzeMarket(symbol, marketData, sessionId) {
        const { price = 0, volume24h = 0, priceChange24h = 0, high24h = 0, low24h = 0 } = marketData;
        const volumeRatio = volume24h / 1000000;
        const pricePosition = high24h > low24h ? (price - low24h) / (high24h - low24h) : 0.5;
        
        let confidence = 0.7;
        if (volumeRatio > 1.3) confidence += 0.15;
        if (volumeRatio > 1.8) confidence += 0.2;
        if (priceChange24h > 3) confidence += 0.2;
        if (priceChange24h > 7) confidence += 0.25;
        if (pricePosition < 0.35) confidence += 0.15;
        if (pricePosition > 0.65) confidence += 0.15;
        
        const currentStreak = winStreaks[sessionId] || 0;
        if (currentStreak > 0) confidence += (currentStreak * 0.05);
        confidence = Math.min(confidence, 0.98);
        
        const action = (pricePosition < 0.35 && priceChange24h > -3 && volumeRatio > 1.1) ? 'BUY' :
                      (pricePosition > 0.65 && priceChange24h > 3 && volumeRatio > 1.1) ? 'SELL' : 
                      (Math.random() > 0.2 ? 'BUY' : 'SELL');
        
        return { symbol, price, confidence, action };
    }

    calculatePositionSize(initialInvestment, currentProfit, targetProfit, timeElapsed, timeLimit, confidence, sessionId) {
        const timeRemaining = Math.max(0.1, (timeLimit - timeElapsed) / timeLimit);
        const remainingProfit = Math.max(1, targetProfit - currentProfit);
        let baseSize = Math.max(10, initialInvestment * 0.25);
        const timePressure = 1.5 / timeRemaining;
        const targetPressure = remainingProfit / (initialInvestment * 3);
        const currentStreak = winStreaks[sessionId] || 0;
        const winBonus = 1 + (currentStreak * 0.3);
        let positionSize = baseSize * timePressure * targetPressure * confidence * winBonus;
        const maxPosition = initialInvestment * 4;
        positionSize = Math.min(positionSize, maxPosition);
        positionSize = Math.max(positionSize, 10);
        return positionSize;
    }
}

// ==================== BINANCE API FOR TRADING (with fixed signature) ====================
const rateLimit = { lastRequestTime: 0, lastOrderTime: 0, bannedUntil: 0, warningCount: 0, timeOffset: 0, lastTimeSync: 0 };

class BinanceAPI {
    static endpoints = {
        base: ['https://api.binance.com', 'https://api1.binance.com', 'https://api2.binance.com', 'https://api3.binance.com', 'https://api4.binance.com'],
        data: ['https://data.binance.com'],
        testnet: ['https://testnet.binance.vision']
    };
    
    static async delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
    
    // FIXED SIGNATURE with percent-encoding
    static signRequest(queryString, secret) {
        const encodedPayload = encodeURIComponent(queryString);
        return crypto.createHmac('sha256', secret).update(encodedPayload).digest('hex');
    }
    
    static async syncTime() {
        try {
            const startTime = Date.now();
            const response = await axios.get('https://api.binance.com/api/v3/time', { timeout: 5000 });
            const endTime = Date.now();
            const serverTime = response.data.serverTime;
            const localTime = (startTime + endTime) / 2;
            rateLimit.timeOffset = serverTime - localTime;
            rateLimit.lastTimeSync = Date.now();
            console.log(`✅ Time synced: offset = ${Math.round(rateLimit.timeOffset)}ms`);
            return rateLimit.timeOffset;
        } catch (e) {
            console.log('⚠️ Time sync failed, using previous offset');
            return rateLimit.timeOffset;
        }
    }
    
    static async getTimestamp() {
        if (Date.now() - rateLimit.lastTimeSync > 300000 || rateLimit.timeOffset === 0) {
            await this.syncTime();
        }
        return Date.now() + rateLimit.timeOffset;
    }
    
    static async rateLimitDelay() {
        const timeSinceLast = Date.now() - rateLimit.lastRequestTime;
        if (timeSinceLast < 1500) await this.delay(1500 - timeSinceLast);
        rateLimit.lastRequestTime = Date.now();
    }
    
    static async makeRequest(endpoint, method, apiKey, secret, params = {}, useTestnet = false) {
        await this.rateLimitDelay();
        if (rateLimit.bannedUntil > Date.now()) throw new Error('IP BANNED');
        
        const timestamp = await this.getTimestamp();
        const queryParams = { ...params, timestamp, recvWindow: 10000 };
        
        // Sort keys alphabetically for consistent signature
        const sortedKeys = Object.keys(queryParams).sort();
        const queryString = sortedKeys.map(k => `${k}=${queryParams[k]}`).join('&');
        
        const signature = this.signRequest(queryString, secret);
        
        const endpointsToTry = useTestnet ? this.endpoints.testnet : this.endpoints.base;
        for (const baseUrl of endpointsToTry) {
            try {
                const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
                const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey.trim() }, timeout: 10000 });
                return response.data;
            } catch (err) { continue; }
        }
        throw new Error('All endpoints failed');
    }
    
    static async getAccountBalance(apiKey, secret, useTestnet = false) {
        try {
            const data = await this.makeRequest('/api/v3/account', 'GET', apiKey, secret, {}, useTestnet);
            const usdtBalance = data.balances.find(b => b.asset === 'USDT');
            return { success: true, free: parseFloat(usdtBalance?.free || 0), total: parseFloat(usdtBalance?.free || 0) };
        } catch (error) { return { success: false, error: error.message }; }
    }
    
    static async getTicker(symbol, useTestnet = false) {
        try {
            const data = await this.makeRequest('/api/v3/ticker/24hr', 'GET', 'dummy', 'dummy', { symbol }, useTestnet);
            return { success: true, data: data };
        } catch (error) { return { success: false, error: error.message }; }
    }
    
    static async placeMarketOrder(apiKey, secret, symbol, side, quoteOrderQty, useTestnet = false) {
        try {
            const orderData = await this.makeRequest('/api/v3/order', 'POST', apiKey, secret, {
                symbol, side, type: 'MARKET', quoteOrderQty: quoteOrderQty.toFixed(2)
            }, useTestnet);
            let avgPrice = 0;
            if (orderData.fills && orderData.fills.length > 0) {
                let totalValue = 0, totalQty = 0;
                orderData.fills.forEach(fill => { totalValue += parseFloat(fill.price) * parseFloat(fill.qty); totalQty += parseFloat(fill.qty); });
                avgPrice = totalValue / totalQty;
            }
            return { success: true, orderId: orderData.orderId, executedQty: parseFloat(orderData.executedQty), price: avgPrice };
        } catch (error) { return { success: false, error: error.message }; }
    }
}

const aiEngine = new AITradingEngine();

// ==================== TRADING STATE PER USER ====================
const userTradingState = {};

app.post('/api/start-trading', authenticate, async (req, res) => {
    const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add your Binance API keys first' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const balance = await BinanceAPI.getAccountBalance(apiKey, secretKey, false);
    if (!balance.success || balance.free < initialInvestment) {
        return res.status(400).json({ success: false, message: `Insufficient balance. Need $${initialInvestment}` });
    }
    const botId = 'bot_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    userTradingState[req.user.email] = {
        botId, initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs,
        startedAt: Date.now(), isRunning: true, currentProfit: 0, trades: [], lastTradeTime: Date.now()
    };
    winStreaks[req.user.email] = 0;
    res.json({ success: true, botId });
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    if (userTradingState[req.user.email]) userTradingState[req.user.email].isRunning = false;
    res.json({ success: true });
});

app.post('/api/trading-update', authenticate, async (req, res) => {
    const state = userTradingState[req.user.email];
    if (!state || !state.isRunning) return res.json({ success: true, currentProfit: 0, newTrades: [] });
    const users = readUsers();
    const user = users[req.user.email];
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const newTrades = [];
    const now = Date.now();
    const timeElapsed = (now - state.startedAt) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, state.timeLimit - timeElapsed);
    const timeSinceLastTrade = (now - (state.lastTradeTime || 0)) / 1000;
    if (timeRemaining > 0 && timeSinceLastTrade >= 90) {
        const symbol = state.tradingPairs[Math.floor(Math.random() * state.tradingPairs.length)] || 'BTCUSDT';
        const tickerData = await BinanceAPI.getTicker(symbol, false);
        if (tickerData.success) {
            const marketPrice = parseFloat(tickerData.data.lastPrice);
            const marketData = {
                price: marketPrice,
                volume24h: parseFloat(tickerData.data.volume),
                priceChange24h: parseFloat(tickerData.data.priceChangePercent),
                high24h: parseFloat(tickerData.data.highPrice),
                low24h: parseFloat(tickerData.data.lowPrice)
            };
            const signal = aiEngine.analyzeMarket(symbol, marketData, req.user.email);
            if (signal.action !== 'HOLD') {
                const positionSize = aiEngine.calculatePositionSize(
                    state.initialInvestment, state.currentProfit, state.targetProfit,
                    timeElapsed, state.timeLimit, signal.confidence, req.user.email
                );
                const orderResult = await BinanceAPI.placeMarketOrder(apiKey, secretKey, symbol, signal.action, positionSize, false);
                if (orderResult.success) {
                    const currentTicker = await BinanceAPI.getTicker(symbol, false);
                    const currentPrice = currentTicker.success ? parseFloat(currentTicker.data.lastPrice) : marketPrice;
                    const entryPrice = orderResult.price || marketPrice;
                    let profit = signal.action === 'BUY' ? (currentPrice - entryPrice) * orderResult.executedQty : (entryPrice - currentPrice) * orderResult.executedQty;
                    if (profit > 0) winStreaks[req.user.email] = (winStreaks[req.user.email] || 0) + 1;
                    else winStreaks[req.user.email] = 0;
                    state.currentProfit += profit;
                    state.lastTradeTime = now;
                    newTrades.push({
                        symbol, side: signal.action, quantity: orderResult.executedQty.toFixed(6),
                        price: entryPrice.toFixed(2), profit: profit, size: '$' + positionSize.toFixed(2),
                        confidence: (signal.confidence * 100).toFixed(0) + '%',
                        winStreak: winStreaks[req.user.email], timestamp: new Date().toISOString()
                    });
                    state.trades.unshift(...newTrades);
                    if (state.currentProfit >= state.targetProfit) state.isRunning = false;
                    const userTradeFile = path.join(tradesDir, req.user.email.replace(/[^a-z0-9]/gi, '_') + '.json');
                    let allTrades = [];
                    if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
                    allTrades.unshift(...newTrades);
                    fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
                }
            }
        }
    }
    if (timeElapsed >= state.timeLimit) state.isRunning = false;
    const balance = await BinanceAPI.getAccountBalance(apiKey, secretKey, false);
    res.json({
        success: true, currentProfit: state.currentProfit || 0,
        timeRemaining: timeRemaining.toFixed(2), targetReached: state.targetReached || false,
        timeExceeded: state.timeExceeded || false, newTrades, balance: balance.free,
        winStreak: winStreaks[req.user.email] || 0
    });
});

// ==================== OWNER ADMIN ENDPOINTS ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const users = readUsers();
    const userList = Object.keys(users).map(email => ({
        email, hasApiKeys: !!users[email].apiKey, createdAt: users[email].createdAt, isOwner: users[email].isOwner, isApproved: users[email].isApproved
    }));
    res.json({ success: true, users: userList });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Only owner can change password' });
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ success: false, message: 'Current and new password required' });
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed successfully! Please login again.' });
});

// Serve frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🌙 Multi-User Halal AI Trading Bot running on port ${PORT}`);
    console.log(`✅ Signature encoding: Percent-encoding enabled (required from Jan 15, 2026)`);
    console.log(`✅ Time sync: Auto-calculates server offset`);
    console.log(`Owner email: mujtabahatif@gmail.com | Password: Mujtabah@2598`);
});
