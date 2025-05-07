const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Student', 'Faculty', 'Admin'], required: true },
  name: { type: String },
  otp: { type: String },
  otpExpires: { type: Date },
});

const marksSchema = new mongoose.Schema({
  email: { type: String, required: true },
  courseName: { type: String, required: true },
  score: { type: Number, required: true },
  name: { type: String },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Marks = mongoose.model('Marks', marksSchema);

module.exports = { User, Marks };
  