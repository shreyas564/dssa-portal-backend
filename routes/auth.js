const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const authenticateToken = require('../middleware/auth');

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

let otps = {};

// Send OTP
router.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = otp;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for DSSA Portal Login',
      text: `Your OTP is: ${otp}`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });

  if (otps[email] !== otp) return res.status(400).json({ error: 'Invalid OTP' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    delete otps[email];
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Register (Send OTP for Registration)
router.post('/register', async (req, res) => {
  const { enrollmentId, rollNo, fullName, yearOfStudy, division, email } = req.body;
  if (!enrollmentId || !rollNo || !fullName || !yearOfStudy || !division || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { enrollmentId }] });
    if (existingUser) return res.status(400).json({ error: 'Email or Enrollment ID already exists' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = { otp, userData: { enrollmentId, rollNo, fullName, yearOfStudy, division, email } };

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP for DSSA Portal Registration',
      text: `Your OTP is: ${otp}`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP and Complete Registration
router.post('/verify-otp-register', async (req, res) => {
  const { email, otp, enrollmentId, rollNo, fullName, yearOfStudy, division } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required' });

  if (!otps[email] || otps[email].otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

  try {
    const userData = otps[email].userData;
    const newUser = new User({
      enrollmentId: userData.enrollmentId,
      rollNo: userData.rollNo,
      fullName: userData.fullName,
      yearOfStudy: userData.yearOfStudy,
      division: userData.division,
      email: userData.email,
      role: 'Student',
    });

    await newUser.save();
    delete otps[email];
    res.json({ message: 'Registration successful' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Verify Token
router.get('/verify-token', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-__v');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch Marks for a Student
router.get('/fetch-marks', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Student') return res.status(403).json({ error: 'Access denied' });

  try {
    const user = await User.findById(req.user.id);
    res.json(user.marks || []);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;