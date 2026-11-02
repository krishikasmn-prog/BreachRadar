const express = require('express');
const ScanHistory = require('./models/ScanHistory');
const AlertSubscription = require('./models/AlertSubscription');
const { checkAndAlert } = require('./utils/alertChecker');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const { body, param, validationResult } = require('express-validator');
const axios = require('axios');
const { execSync } = require('child_process');
const cron = require('node-cron');
const path = require('path');

const fs = require('fs');
const envPath = path.join(__dirname, '.env');
dotenv.config({ path: envPath });
if (!fs.existsSync(envPath)) {
  console.error('\n[SETUP PROBLEM] No ".env" file found in: ' + __dirname);
  const files = fs.readdirSync(__dirname).filter(f => f.toLowerCase().startsWith('.env'));
  console.error('Files starting with ".env" in that folder: ' + (files.length ? files.join(', ') : 'none'));
  console.error('Fix: the file must be named exactly ".env" (not ".env.txt" or ".env.example").\n');
} else if (!process.env.MONGODB_URI) {
  console.error('\n[SETUP PROBLEM] .env was found but MONGODB_URI is empty. It must look like:');
  console.error('MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/dbname   (no spaces, no quotes)\n');
}



const app = express();
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("Backend is live 🚀");
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || '')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Validation Middleware
const validateEmail = [
  body('email').isEmail().withMessage('Valid email is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
  }
];

const validateEmailParam = [
  param('email').isEmail().withMessage('Valid email is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    next();
  }
];

// Routes

// Risk scoring helper
const calculateRisk = (breaches) => {
  if (!breaches || breaches.length === 0) return 0;

  let maxBreachScore = 0;
  const twoYearsAgo = new Date();
  twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);

  const sensitiveTypes = {
    'Passwords': 35, 'Credit card details': 35, 'Partial credit card data': 20,
    'Social security numbers': 40, 'Government IDs': 35, 'Bank account numbers': 35,
    'Phone numbers': 15, 'Physical addresses': 15, 'Dates of birth': 12,
    'Email addresses': 8, 'Usernames': 8, 'Names': 5, 'IP addresses': 5,
    'Geographic locations': 5, 'Social media profiles': 5, 'Device information': 5,
  };

  let hasRecentBreach = false;

  breaches.forEach(b => {
    let currentBreachScore = 0;
    const dataTypes = (b.xposed_data || '').split(';').map(s => s.trim());

    // Sum up score for THIS breach
    dataTypes.forEach(dt => { currentBreachScore += sensitiveTypes[dt] || 4; });

    // Cap a single breach base score to 75
    currentBreachScore = Math.min(currentBreachScore, 75);

    if (currentBreachScore > maxBreachScore) {
      maxBreachScore = currentBreachScore;
    }

    const yr = parseInt(b.xposed_date, 10);
    const bdate = new Date(yr, 0, 1);
    if (bdate >= twoYearsAgo) hasRecentBreach = true;
  });

  // Base score is the worst breach. Then add a diminishing penalty for additional breaches.
  // Cap the volume penalty to 15 max.
  const volumePenalty = Math.min(breaches.length, 15);

  let totalScore = maxBreachScore + volumePenalty;
  if (hasRecentBreach) totalScore += 10; // add 10 if there's a recent breach

  return Math.min(Math.round(totalScore), 100);
};

// 1. POST /api/scan — uses XposedOrNot (completely free, no key required)
app.post('/api/scan', validateEmail, async (req, res) => {
  const { email } = req.body;
  try {
    // Step 1: Check if email has been exposed
    let checkResp;
    try {
      checkResp = await axios.get(
        `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`,
        { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' }, timeout: 10000 }
      );
    } catch (err) {
      if (err.response?.status === 404 || err.response?.data?.Error === 'Not found') {
        // Clean email — not in any known breach
        const safeRecord = new ScanHistory({ email, breachCount: 0, riskScore: 0, severity: 'Safe', breaches: [] });
        await safeRecord.save();
        return res.json(safeRecord);
      }
      throw err;
    }

    const breachNames = checkResp.data?.breaches?.[0] || [];
    if (breachNames.length === 0) {
      const safeRecord = new ScanHistory({ email, breachCount: 0, riskScore: 0, severity: 'Safe', breaches: [] });
      await safeRecord.save();
      return res.json(safeRecord);
    }

    // Step 2: Get detailed breach info
    let detailedBreaches = [];
    try {
      const detailResp = await axios.get(
        `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`,
        { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' }, timeout: 15000 }
      );
      detailedBreaches = detailResp.data?.ExposedBreaches?.breaches_details || [];
    } catch (err) {
      // If analytics fails, build minimal breach list from names
      detailedBreaches = breachNames.map(name => ({ breach: name, xposed_data: 'Email addresses', xposed_date: 'Unknown', xposed_records: 0, domain: '', details: '' }));
    }

    const riskScore = calculateRisk(detailedBreaches);
    let severity = 'Safe';
    if (riskScore > 70) severity = 'Critical';
    else if (riskScore > 40) severity = 'High';
    else if (riskScore > 15) severity = 'Medium';
    else if (riskScore > 0) severity = 'Low';

    const formattedBreaches = detailedBreaches.map(b => ({
      name: b.breach,
      domain: b.domain || '',
      breachDate: b.xposed_date || 'Unknown',
      dataClasses: (b.xposed_data || 'Email addresses').split(';').map(s => s.trim()),
      pwnCount: b.xposed_records || 0,
      description: b.details || '',
      logoPath: b.logo || '',
      verified: b.verified === 'Yes',
      passwordRisk: b.password_risk || 'unknown',
    }));

    const newScan = new ScanHistory({ email, breachCount: formattedBreaches.length, riskScore, severity, breaches: formattedBreaches });
    await newScan.save();
    res.json(newScan);
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(500).json({ error: 'Scan failed. The breach database may be temporarily unavailable. Try again in a moment.' });
  }
});

// 2. GET /api/history/:email
app.get('/api/history/:email', validateEmailParam, async (req, res) => {
  const { email } = req.params;
  try {
    const history = await ScanHistory.find({ email }).sort({ scanDate: -1 }).limit(10);
    res.json(history);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 3. POST /api/subscribe
app.post('/api/subscribe', validateEmail, async (req, res) => {
  const { email } = req.body;
  try {
    const existing = await AlertSubscription.findOne({ email });
    if (existing) {
      existing.isActive = true;
      await existing.save();
    } else {
      await AlertSubscription.create({ email });
    }
    res.json({ message: 'Subscribed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 4. DELETE /api/unsubscribe/:email
app.delete('/api/unsubscribe/:email', validateEmailParam, async (req, res) => {
  const { email } = req.params;
  try {
    const sub = await AlertSubscription.findOne({ email });
    if (sub) {
      sub.isActive = false;
      await sub.save();
    }
    res.json({ message: 'Unsubscribed' });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 4.5 GET /api/subscription/:email
app.get('/api/subscription/:email', validateEmailParam, async (req, res) => {
  const { email } = req.params;
  try {
    const sub = await AlertSubscription.findOne({ email });
    res.json({ isActive: sub ? sub.isActive : false });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 5. GET /api/stats
app.get('/api/stats', async (req, res) => {
  try {
    const totalScans = await ScanHistory.countDocuments();
    const allScans = await ScanHistory.find({}, 'breachCount severity');

    const totalBreaches = allScans.reduce((acc, scan) => acc + (scan.breachCount || 0), 0);
    const criticalCount = allScans.filter(scan => scan.severity === 'Critical').length;

    res.json({ totalScans, totalBreaches, criticalCount });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Cron job
cron.schedule('0 9 * * *', checkAndAlert);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});