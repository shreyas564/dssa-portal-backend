const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { User, Marks } = require('./models');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://dssa-portal:pass1234@dssa-portal.qvqwj.mongodb.net/?retryWrites=true&w=majority&appName=dssa-portal';

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Connect to MongoDB
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { email, password, role, name } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword, role, name });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'DSSA Portal OTP',
      text: `Your OTP for login is ${otp}. It is valid for 10 minutes.`,
    });

    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Login with OTP endpoint
app.post('/login', async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    user.otp = null;
    user.otpExpires = null;
    await user.save();

    const token = jwt.sign({ email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, email: user.email, role: user.role, name: user.name });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify token endpoint
app.get('/verify-token', verifyToken, (req, res) => {
  res.status(200).json({ email: req.user.email, role: req.user.role, name: req.user.name });
});

// Store marks endpoint (secured with JWT)
app.post('/store-marks', verifyToken, async (req, res) => {
  const { email, courseName, score, name } = req.body;
  if (!email || !courseName || !score) {
    return res.status(400).json({ error: 'Email, courseName, and score are required' });
  }

  try {
    const marks = new Marks({ email, courseName, score, name, timestamp: new Date() });
    await marks.save();
    res.status(201).json({ message: 'Marks stored successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to store marks' });
  }
});

// Fetch marks endpoint
app.get('/fetch-marks', verifyToken, async (req, res) => {
  try {
    const marks = await Marks.find({ email: req.user.email });
    res.status(200).json(marks);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch marks' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));