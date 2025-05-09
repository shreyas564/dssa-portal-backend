const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authenticateToken = require('../middleware/auth');

// Fetch All Students (for Faculty Dashboard)
router.get('/fetch-all-students', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Faculty') return res.status(403).json({ error: 'Access denied' });

  try {
    const students = await User.find({ role: 'Student' }).select('enrollmentId rollNo fullName yearOfStudy division email marks').lean();
    res.json(students);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;