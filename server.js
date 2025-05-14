const express = require('express');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'https://dssa-portal-frontend.onrender.com' }));

const client = new MongoClient(process.env.MONGODB_URI);
const db = client.db('npteldb');
const usersCollection = db.collection('users');
const otpsCollection = db.collection('otps');
const marksCollection = db.collection('marks');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// Check if user is registered
app.post('/check-user', async (req, res) => {
  const { email } = req.body;
  console.log('Received /check-user request:', { email });
  if (!email) {
    console.error('Missing email');
    return res.status(400).json({ error: 'Email required' });
  }

  try {
    const user = await usersCollection.findOne({ email, role: { $in: ['Student', 'Faculty', 'Admin'] } });
    if (user) {
      console.log('User found:', email);
      res.json({ isRegistered: true });
    } else {
      console.log('User not found:', email);
      res.json({ isRegistered: false });
    }
  } catch (error) {
    console.error('Error in /check-user:', error.message);
    res.status(500).json({ error: 'Failed to check user' });
  }
});

// Register: Send OTP (for Students)
app.post('/register', async (req, res) => {
  const { enrollmentId, rollNo, fullName, yearOfStudy, division, email } = req.body;
  console.log('Received /register request:', { enrollmentId, rollNo, fullName, yearOfStudy, division, email });
  if (!enrollmentId || !rollNo || !fullName || !yearOfStudy || !division || !email) {
    console.error('Missing required fields');
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existingUser = await usersCollection.findOne({ $or: [{ email }, { enrollmentId }] });
    if (existingUser) {
      console.log('Email or Enrollment ID already registered:', { email, enrollmentId });
      return res.status(400).json({ error: 'Email or Enrollment ID already registered' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated OTP:', otp);
    await otpsCollection.insertOne({
      enrollmentId,
      rollNo,
      fullName,
      yearOfStudy,
      division,
      email,
      otp,
      createdAt: new Date(),
      purpose: 'register',
      role: 'Student',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes expiry
    });
    console.log('OTP stored in database for:', email);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'DSSA Portal Registration OTP',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });
    console.log('OTP email sent to:', email);

    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error in /register:', error.message);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP and complete registration (for Students)
app.post('/verify-otp-register', async (req, res) => {
  const { email, otp } = req.body;
  console.log('Received /verify-otp-register request:', { email, otp });
  if (!email || !otp) {
    console.error('Missing email or OTP');
    return res.status(400).json({ error: 'Email and OTP required' });
  }

  try {
    const otpRecord = await otpsCollection.findOne({ email, otp, purpose: 'register' });
    if (!otpRecord) {
      console.log('Invalid OTP for:', email);
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    const now = new Date();
    if (now > new Date(otpRecord.expiresAt)) {
      console.log('OTP expired for:', email);
      await otpsCollection.deleteOne({ email, otp });
      return res.status(400).json({ error: 'OTP expired' });
    }

    await usersCollection.insertOne({
      enrollmentId: otpRecord.enrollmentId,
      rollNo: otpRecord.rollNo,
      fullName: otpRecord.fullName,
      yearOfStudy: otpRecord.yearOfStudy,
      division: otpRecord.division,
      email,
      role: 'Student',
      createdAt: new Date(),
    });
    console.log('User registered:', email);

    await otpsCollection.deleteOne({ email, otp });
    console.log('OTP record deleted for:', email);

    res.json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Error in /verify-otp-register:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Send OTP for login (for Students, Faculty, and Admins)
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  console.log('Received /send-otp request:', { email });
  if (!email) {
    console.error('Missing email');
    return res.status(400).json({ error: 'Email required' });
  }

  try {
    const user = await usersCollection.findOne({ email, role: { $in: ['Student', 'Faculty', 'Admin'] } });
    if (!user) {
      console.log('Email not registered or invalid role:', email);
      return res.status(400).json({ error: 'Email not registered or invalid role' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated OTP for login:', otp);
    await otpsCollection.insertOne({
      email,
      otp,
      createdAt: new Date(),
      purpose: 'login',
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes expiry
    });
    console.log('OTP stored in database for login:', email);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'DSSA Portal Login OTP',
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });
    console.log('Login OTP email sent to:', email);

    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Error in /send-otp:', error.message);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Login: Verify OTP (for Students, Faculty, and Admins)
app.post('/login', async (req, res) => {
  const { email, otp } = req.body;
  console.log('Received /login request:', { email, otp });
  if (!email || !otp) {
    console.error('Missing email or OTP');
    return res.status(400).json({ error: 'Email and OTP required' });
  }

  try {
    const otpRecord = await otpsCollection.findOne({ email, otp, purpose: 'login' });
    if (!otpRecord) {
      console.log('Invalid OTP for login:', email);
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    const now = new Date();
    if (now > new Date(otpRecord.expiresAt)) {
      console.log('OTP expired for login:', email);
      await otpsCollection.deleteOne({ email, otp });
      return res.status(400).json({ error: 'OTP expired' });
    }

    const user = await usersCollection.findOne({ email, role: { $in: ['Student', 'Faculty', 'Admin'] } });
    if (!user) {
      console.log('Email not registered or invalid role during login:', email);
      return res.status(400).json({ error: 'Email not registered or invalid role' });
    }

    const token = jwt.sign({ email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log('JWT generated for:', email);
    await otpsCollection.deleteOne({ email, otp });
    console.log('Login OTP record deleted for:', email);

    res.json({ token });
  } catch (error) {
    console.error('Error in /login:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Store marks: Validate registered email only
app.post('/store-marks', async (req, res) => {
  const { name, email, score, courseName } = req.body;
  console.log('Received /store-marks request:', { name, email, score, courseName });

  try {
    const user = await usersCollection.findOne({ email, role: 'Student' });
    if (!user) {
      console.log('Email not registered for /store-marks:', email);
      return res.status(400).json({ error: 'Email not registered' });
    }

    const existingMark = await marksCollection.findOne({ email, courseName });
    if (existingMark) {
      console.log('Marks already present for:', { email, courseName });
      return res.status(400).json({ error: 'Marks already present for this course', message: 'Marks already present' });
    }

    await marksCollection.insertOne({
      name,
      email,
      score,
      courseName,
      timestamp: new Date(),
    });
    console.log('Marks stored for:', { email, courseName });

    res.json({ message: 'Marks stored successfully' });
  } catch (error) {
    console.error('Error in /store-marks:', error.message);
    res.status(500).json({ error: 'Failed to store marks' });
  }
});

// Verify token (for Students, Faculty, and Admins)
app.get('/verify-token', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /verify-token request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /verify-token');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await usersCollection.findOne({ email: decoded.email, role: { $in: ['Student', 'Faculty', 'Admin'] } });
    if (!user) {
      console.log('User not found for /verify-token:', decoded.email);
      return res.status(401).json({ error: 'User not found' });
    }
    res.json({
      enrollmentId: user.enrollmentId,
      rollNo: user.rollNo,
      fullName: user.fullName,
      yearOfStudy: user.yearOfStudy,
      division: user.division,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    console.error('Error in /verify-token:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Fetch marks (for Students)
app.get('/fetch-marks', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /fetch-marks request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /fetch-marks');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Student') {
      console.log('Unauthorized role for /fetch-marks:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }
    const marks = await marksCollection.find({ email: decoded.email }).toArray();
    console.log('Marks fetched for:', decoded.email);
    res.json(marks);
  } catch (error) {
    console.error('Error in /fetch-marks:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Fetch all students with marks (for Faculty, legacy endpoint)
app.get('/fetch-all-students', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /fetch-all-students request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /fetch-all-students');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /fetch-all-students:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const students = await usersCollection.find({ role: 'Student' }).toArray();
    const studentEmails = students.map(student => student.email);
    const marks = await marksCollection.find({ email: { $in: studentEmails } }).toArray();

    const studentsWithMarks = students.map(student => ({
      ...student,
      marks: marks.filter(mark => mark.email === student.email),
    }));

    console.log('Students with marks fetched for Faculty:', decoded.email);
    res.json(studentsWithMarks);
  } catch (error) {
    console.error('Error in /fetch-all-students:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Fetch all marks (for Faculty, legacy endpoint)
app.get('/fetch-all-marks', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /fetch-all-marks request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /fetch-all-marks');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /fetch-all-marks:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }
    const marks = await marksCollection.find().toArray();
    console.log('All marks fetched for Faculty:', decoded.email);
    res.json(marks);
  } catch (error) {
    console.error('Error in /fetch-all-marks:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Faculty: Fetch unique years of study
app.get('/faculty/years', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /faculty/years request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /faculty/years');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /faculty/years:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const years = await usersCollection.distinct('yearOfStudy', { role: 'Student' });
    console.log('Years fetched for Faculty:', years);
    res.json(years);
  } catch (error) {
    console.error('Error in /faculty/years:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Faculty: Fetch unique divisions for a given year
app.get('/faculty/divisions', async (req, res) => {
  const authHeader = req.headers.authorization;
  let { year } = req.query;
  console.log('Received /faculty/divisions request:', {
    year,
    authHeader: authHeader ? authHeader.substring(0, 20) + '...' : 'Missing'
  });

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /faculty/divisions');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!year) {
    console.error('Missing year parameter');
    return res.status(400).json({ error: 'Year parameter required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('JWT decoded:', { email: decoded.email, role: decoded.role });

    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /faculty/divisions:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    // Normalize year: Remove spaces (e.g., "Third Year" -> "ThirdYear")
    year = year.replace(/\s/g, '');
    console.log('Normalized year:', year);

    // Log the query being executed
    console.log('Querying users collection for:', { role: 'Student', yearOfStudy: year });

    // Query distinct divisions for the given year
    const divisions = await usersCollection.distinct('division', { role: 'Student', yearOfStudy: year });
    console.log('Divisions fetched for year:', year, divisions);

    if (!divisions || divisions.length === 0) {
      console.log('No divisions found for year:', year);
      return res.status(404).json({ error: 'No divisions found for this year' });
    }

    // Sort divisions alphabetically
    divisions.sort();
    res.json(divisions);
  } catch (error) {
    console.error('Error in /faculty/divisions:', {
      message: error.message,
      stack: error.stack
    });
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Failed to fetch divisions' });
  }
});

// Faculty: Fetch roll numbers for a given year and division
app.get('/faculty/roll-nos', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { year, division } = req.query;
  console.log('Received /faculty/roll-nos request:', { year, division });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /faculty/roll-nos');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!year || !division) {
    console.error('Missing year or division parameter');
    return res.status(400).json({ error: 'Year and division parameters required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /faculty/roll-nos:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const students = await usersCollection.find({ role: 'Student', yearOfStudy: year, division }).toArray();
    const rollNos = students.map(student => ({
      rollNo: student.rollNo,
      email: student.email, // Include email to fetch marks later
    }));
    console.log('Roll numbers fetched for Faculty:', rollNos);
    res.json(rollNos);
  } catch (error) {
    console.error('Error in /faculty/roll-nos:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Faculty: Fetch marks for a specific student
app.get('/faculty/student-marks', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { email } = req.query;
  console.log('Received /faculty/student-marks request:', { email });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /faculty/student-marks');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!email) {
    console.error('Missing email parameter');
    return res.status(400).json({ error: 'Email parameter required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Faculty') {
      console.log('Unauthorized role for /faculty/student-marks:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const student = await usersCollection.findOne({ email, role: 'Student' });
    if (!student) {
      console.log('Student not found for /faculty/student-marks:', email);
      return res.status(404).json({ error: 'Student not found' });
    }

    const marks = await marksCollection.find({ email }).toArray();
    const studentData = {
      enrollmentId: student.enrollmentId,
      rollNo: student.rollNo,
      fullName: student.fullName,
      yearOfStudy: student.yearOfStudy,
      division: student.division,
      email: student.email,
      marks,
    };

    console.log('Student marks fetched for Faculty:', email);
    res.json(studentData);
  } catch (error) {
    console.error('Error in /faculty/student-marks:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch all users
app.get('/admin/users', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /admin/users GET request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/users');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/users:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const users = await usersCollection.find().toArray();
    console.log('Users fetched for Admin:', decoded.email);
    res.json(users);
  } catch (error) {
    console.error('Error in /admin/users GET:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch users by role
app.get('/admin/users-by-role', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { role } = req.query;
  console.log('Received /admin/users-by-role request:', { role });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/users-by-role');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!role) {
    console.error('Missing role parameter');
    return res.status(400).json({ error: 'Role parameter required' });
  }
  if (!['Admin', 'Faculty', 'Student'].includes(role)) {
    console.error('Invalid role parameter:', role);
    return res.status(400).json({ error: 'Invalid role' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/users-by-role:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const users = await usersCollection.find({ role }).toArray();
    console.log(`Users fetched for role ${role} by Admin:`, decoded.email);
    res.json(users);
  } catch (error) {
    console.error('Error in /admin/users-by-role:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch years of study for students
app.get('/admin/student-years', async (req, res) => {
  const authHeader = req.headers.authorization;
  console.log('Received /admin/student-years request');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/student-years');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/student-years:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    // Hardcode the years as requested: 1st Year, 2nd Year, 3rd Year, 4th Year
    const years = ['First', 'Second', 'Third', 'Fourth'];
    console.log('Years fetched for Admin:', years);
    res.json(years);
  } catch (error) {
    console.error('Error in /admin/student-years:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch divisions for a given year
app.get('/admin/student-divisions', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { year } = req.query;
  console.log('Received /admin/student-divisions request:', { year });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/student-divisions');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!year) {
    console.error('Missing year parameter');
    return res.status(400).json({ error: 'Year parameter required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/student-divisions:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const divisions = await usersCollection.distinct('division', { role: 'Student', yearOfStudy: year });
    console.log('Divisions fetched for Admin:', divisions);
    res.json(divisions);
  } catch (error) {
    console.error('Error in /admin/student-divisions:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch roll numbers for a given year and division
app.get('/admin/student-roll-nos', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { year, division } = req.query;
  console.log('Received /admin/student-roll-nos request:', { year, division });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/student-roll-nos');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!year || !division) {
    console.error('Missing year or division parameter');
    return res.status(400).json({ error: 'Year and division parameters required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/student-roll-nos:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const students = await usersCollection.find({ role: 'Student', yearOfStudy: year, division }).toArray();
    const rollNos = students.map(student => ({
      rollNo: student.rollNo,
      email: student.email, // Include email to fetch details later
    }));
    console.log('Roll numbers fetched for Admin:', rollNos);
    res.json(rollNos);
  } catch (error) {
    console.error('Error in /admin/student-roll-nos:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Fetch details for a specific student (without marks)
app.get('/admin/student-details', async (req, res) => {
  const authHeader = req.headers.authorization;
  const { email } = req.query;
  console.log('Received /admin/student-details request:', { email });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/student-details');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!email) {
    console.error('Missing email parameter');
    return res.status(400).json({ error: 'Email parameter required' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/student-details:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const student = await usersCollection.findOne({ email, role: 'Student' });
    if (!student) {
      console.log('Student not found for /admin/student-details:', email);
      return res.status(404).json({ error: 'Student not found' });
    }

    const studentData = {
      _id: student._id.toString(), // Add _id as a string
      enrollmentId: student.enrollmentId,
      rollNo: student.rollNo,
      fullName: student.fullName,
      yearOfStudy: student.yearOfStudy,
      division: student.division,
      email: student.email,
      role: student.role,
    };

    console.log('Student details fetched for Admin:', email);
    res.json(studentData);
  } catch (error) {
    console.error('Error in /admin/student-details:', error.message);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin: Update user
app.put('/admin/users/:id', async (req, res) => {
  const authHeader = req.headers.authorization;
  const userId = req.params.id;
  const { enrollmentId, rollNo, fullName, yearOfStudy, division, email, role } = req.body;
  console.log('Received /admin/users PUT request:', { userId, enrollmentId, rollNo, fullName, yearOfStudy, division, email, role });

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/users PUT');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/users PUT:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    let objectId;
    try {
      objectId = new ObjectId(userId);
    } catch (idError) {
      console.error('Invalid userId format:', userId, idError.message);
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    const updateData = {};
    if (enrollmentId !== undefined) updateData.enrollmentId = enrollmentId;
    if (rollNo !== undefined) updateData.rollNo = rollNo;
    if (fullName !== undefined) updateData.fullName = fullName;
    if (yearOfStudy !== undefined) updateData.yearOfStudy = yearOfStudy;
    if (division !== undefined) updateData.division = division;
    if (email) updateData.email = email;
    if (role) updateData.role = role;

    if (Object.keys(updateData).length === 0) {
      console.log('No fields provided to update for userId:', userId);
      return res.status(400).json({ error: 'No fields provided to update' });
    }

    console.log('Update data:', updateData);

    const result = await usersCollection.updateOne(
      { _id: objectId },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      console.log('User not found for update:', userId);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User updated by Admin:', userId);
    const updatedUser = await usersCollection.findOne({ _id: objectId });
    res.json(updatedUser);
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      console.error('JWT verification failed:', error.message);
      return res.status(401).json({ error: 'Invalid token' });
    }
    console.error('Error in /admin/users PUT:', error.message);
    res.status(500).json({ error: 'Failed to update user', details: error.message });
  }
});

// Admin: Delete user
app.delete('/admin/users/:id', async (req, res) => {
  const authHeader = req.headers.authorization;
  const userId = req.params.id;
  console.log('Received /admin/users DELETE request:', { userId });
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('Missing or invalid authorization header for /admin/users DELETE');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'Admin') {
      console.log('Unauthorized role for /admin/users DELETE:', decoded.role);
      return res.status(403).json({ error: 'Unauthorized role' });
    }

    const result = await usersCollection.deleteOne({ _id: new ObjectId(userId) });
    if (result.deletedCount === 0) {
      console.log('User not found for deletion:', userId);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User deleted by Admin:', userId);
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Error in /admin/users DELETE:', error.message);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    console.log(`Server running on port ${PORT}`);
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error.message);
    process.exit(1);
  }
});
