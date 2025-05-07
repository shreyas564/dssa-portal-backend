const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { User, Marks } = require('./models');

<<<<<<< HEAD
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
=======
  const app = express();

  // Middleware
  app.use(cors()); // Allow cross-origin requests (simple setup like the old backend)
  app.use(express.json()); // Parse JSON bodies

  // MongoDB connection
  mongoose.connect('mongodb+srv://npteluser:EZ4GQTlrLDQfFyW2@cluster0.oiegs.mongodb.net/dssa_portal?retryWrites=true&w=majority&appName=Cluster0')
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

  // API endpoint to store marks (aligned with /store-data)
  // API endpoint to store marks
  app.post('/store-marks', async (req, res) => {
    const { name, email, score, courseName } = req.body;

    if (!name || !email || score == null) {
      return res.status(400).json({ error: 'Name, email, and score are required' });
    }

    try {
      // Check if a mark entry exists for this email and courseName
      let mark = await Marks.findOne({ email, courseName });

      if (mark) {
        // Update existing mark for the specific course
        mark.name = name;
        mark.score = score;
        mark.timestamp = new Date();
        await mark.save();
        res.status(200).json({ message: 'Mark data updated successfully' });
      } else {
        // Create new mark for a new course
        mark = new Marks({ name, email, score, courseName, timestamp: new Date() });
        await mark.save();
        res.status(201).json({ message: 'Mark data stored successfully' });
      }
    } catch (error) {
      console.error('Error storing data:', error);
      res.status(500).json({ error: 'Failed to store data' });
    }
  });
  app.post('/register', async (req, res) => {
    const { email, password, role, name } = req.body;
    if (!email || !password || !role) return res.status(400).json({ error: 'Missing required fields' });
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
      const user = new User({ email, password: hashedPassword, role, name });
      await user.save();
      res.json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(400).json({ error: 'User already exists' });
    }
  });
>>>>>>> 27381dd5a68a8d701d316bcf4b61a0f24ae44fea

// Send OTP endpoint
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
<<<<<<< HEAD
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
=======
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ email: user.email, role: user.role }, 'secret', { expiresIn: '1h' });
    res.json({ token, email: user.email, role: user.role, name: user.name });
  });

  app.get('/verify-token', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
      const decoded = jwt.verify(token, 'secret');
      const user = await User.findOne({ email: decoded.email });
      res.json({ email: user.email, role: user.role, name: user.name });
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  });

  app.get('/fetch-marks', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
      const decoded = jwt.verify(token, 'secret');
      const marks = await Marks.find({ email: decoded.email });
      res.json(marks);
    } catch (error) {
      res.status(401).json({ error: 'Invalid token' });
    }
  });

  app.listen(process.env.PORT || 3000, () => console.log('Server running'));
>>>>>>> 27381dd5a68a8d701d316bcf4b61a0f24ae44fea
