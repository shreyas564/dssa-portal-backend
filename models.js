const mongoose = require('mongoose');

  const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Student', 'Faculty', 'Admin'], required: true },
    name: String,
    otp: String,
    otpExpires: Date,
  });

const marksSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  courseName: { type: String },
  score: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now },
});

  module.exports = {
    User: mongoose.model('User', userSchema),
    Marks: mongoose.model('Marks', marksSchema),
  };
