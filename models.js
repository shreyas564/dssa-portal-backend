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
<<<<<<< HEAD
  email: { type: String, required: true },
  courseName: { type: String, required: true },
  score: { type: Number, required: true },
  name: { type: String },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Marks = mongoose.model('Marks', marksSchema);

module.exports = { User, Marks };
  
=======
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
>>>>>>> 27381dd5a68a8d701d316bcf4b61a0f24ae44fea
