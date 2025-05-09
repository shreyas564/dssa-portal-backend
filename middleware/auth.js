const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const User = require('../models/User');
const authenticateToken = require('../middleware/auth');

// Configure SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

let otps = {};

// Test Email Route
router.get('/test-email', async (req, res) => {
  const msg = {
    to: process.env.EMAIL_USER,
    from: process.env.EMAIL_USER,
    subject: 'Test Email from DSSA Portal',
    text: 'This is a test email to verify email sending functionality.',
  };

  try {
    const info = await sgMail.send(msg);
    console.log('Test email sent:', info);
    res.json({ message: 'Test email sent successfully', info });
  } catch (err) {
    console.error('Test email error:', err);
    res.status(500).json({ error: 'Failed to send test email', details: err.message });
  }
});

// Send OTP
router.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = otp;

    const msg = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: 'Your OTP for DSSA Portal Login',
      text: `Your OTP is: ${otp}`,
    };

    const info = await sgMail.send(msg);
    console.log('OTP email sent:', info);
    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error('Error sending OTP email:', err);
    res.status(500).json({ error: 'Failed to send OTP', details: err.message });
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

    const msg = {
      to: email,
      from: process.env.EMAIL_USER,
      subject: 'Your OTP for DSSA Portal Registration',
      text: `Your OTP is: ${otp}`,
    };

    const info = await sgMail.send(msg);
    console.log('Registration OTP email sent:', info);
    res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error('Error sending registration OTP email:', err);
    res.status(500).json({ error: 'Failed to send OTP', details: err.message });
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
