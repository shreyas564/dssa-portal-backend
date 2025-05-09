const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  enrollmentId: { type: String, required: true, unique: true },
  rollNo: { type: String, required: true },
  fullName: { type: String, required: true },
  yearOfStudy: { type: String, required: true },
  division: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  role: { type: String, default: 'Student', enum: ['Student', 'Faculty', 'Admin'] },
  marks: [
    {
      courseName: { type: String, required: true },
      score: { type: Number, required: true },
      timestamp: { type: Date, default: Date.now },
    }
  ],
});

module.exports = mongoose.model('User', userSchema);