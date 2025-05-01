const express = require('express');
  const mongoose = require('mongoose');
  const bcrypt = require('bcrypt');
  const jwt = require('jsonwebtoken');
  const cors = require('cors');
  const { User, Marks } = require('./models');

  const app = express();
  app.use(express.json());

  // Configure CORS to allow all origins (for development; tighten in production)
  app.use(cors({
    origin: '*', // Allows all origins, including chrome-extension://...
    methods: ['GET', 'POST', 'OPTIONS'], // Explicitly allow OPTIONS for preflight
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));

  // Handle preflight requests
  app.options('/store-marks', cors()); // Enable CORS for OPTIONS requests

  mongoose.connect('mongodb+srv://npteluser:EZ4GQTlrLDQfFyW2@cluster0.oiegs.mongodb.net/dssa_portal?retryWrites=true&w=majority&appName=Cluster0');

  app.post('/register', async (req, res) => {
    const { email, password, role, name } = req.body;
    if (!email || !password || !role) return res.status(400).send('Missing required fields');
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
      const user = new User({ email, password: hashedPassword, role, name });
      await user.save();
      res.send('User registered successfully');
    } catch (error) {
      res.status(400).send('User already exists');
    }
  });

  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ email: user.email, role: user.role }, 'secret', { expiresIn: '1h' });
    res.json({ token, email: user.email, role: user.role, name: user.name });
  });

  app.get('/verify-token', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No token provided');
    try {
      const decoded = jwt.verify(token, 'secret');
      const user = await User.findOne({ email: decoded.email });
      res.json({ email: user.email, role: user.role, name: user.name });
    } catch (error) {
      res.status(401).send('Invalid token');
    }
  });

  app.post('/store-marks', async (req, res) => {
    const { email, courseName, score } = req.body;
    if (!email || !courseName || score == null) {
      return res.status(400).send('Missing required fields');
    }
    const mark = new Marks({ email, courseName, score, timestamp: new Date() });
    await mark.save();
    res.send('Mark stored successfully');
  });

  app.get('/fetch-marks', async (req, res) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).send('No token provided');
    try {
      const decoded = jwt.verify(token, 'secret');
      const marks = await Marks.find({ email: decoded.email });
      res.json(marks);
    } catch (error) {
      res.status(401).send('Invalid token');
    }
  });

  app.listen(process.env.PORT || 3000, () => console.log('Server running'));
