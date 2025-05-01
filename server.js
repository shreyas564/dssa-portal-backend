const express = require('express');
  const mongoose = require('mongoose');
  const bcrypt = require('bcrypt');
  const jwt = require('jsonwebtoken');
  const cors = require('cors');
  const { User, Marks } = require('./models');

  const app = express();

  // Middleware
  app.use(cors()); // Allow cross-origin requests (simple setup like the old backend)
  app.use(express.json()); // Parse JSON bodies

  // MongoDB connection
  mongoose.connect('mongodb+srv://npteluser:EZ4GQTlrLDQfFyW2@cluster0.oiegs.mongodb.net/dssa_portal?retryWrites=true&w=majority&appName=Cluster0')
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB connection error:', err));

  // API endpoint to store marks (aligned with /store-data)
  app.post('/store-marks', async (req, res) => {
    const { name, email, score } = req.body;

    if (!name || !email || score == null) {
      return res.status(400).json({ error: 'Name, email, and score are required' });
    }

    try {
      // Check if a mark entry exists for this email and course
      let mark = await Marks.findOne({ email });

      if (mark) {
        // Update existing mark
        mark.name = name;
        mark.score = score;
        mark.timestamp = new Date();
        await mark.save();
        res.status(200).json({ message: 'Mark data updated successfully' });
      } else {
        // Create new mark
        mark = new Marks({ name, email, score, timestamp: new Date() });
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

  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
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
