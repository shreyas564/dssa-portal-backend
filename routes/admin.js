const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authenticateToken = require('../middleware/auth');

// Fetch All Users (for Admin Dashboard)
router.get('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const users = await User.find().select('-__v').lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update User
router.put('/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      {
        enrollmentId: req.body.enrollmentId,
        rollNo: req.body.rollNo,
        fullName: req.body.fullName,
        yearOfStudy: req.body.yearOfStudy,
        division: req.body.division,
        email: req.body.email,
        role: req.body.role,
      },
      { new: true }
    ).select('-__v');
    if (!updatedUser) return res.status(404).json({ error: 'User not found' });
    res.json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete User
router.delete('/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') return res.status(403).json({ error: 'Access denied' });

  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;