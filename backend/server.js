const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/bugtracker';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['reporter', 'admin'], default: 'reporter' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Bug Schema
const bugSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  severity: { 
    type: String, 
    enum: ['Low', 'Medium', 'High'], 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['Open', 'In Progress', 'Closed'], 
    default: 'Open' 
  },
  reportedBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Bug = mongoose.model('Bug', bugSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Create default users on startup
const createDefaultUsers = async () => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    const reporterExists = await User.findOne({ role: 'reporter' });

    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        username: 'admin',
        email: 'admin@bugtracker.com',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('Default admin user created');
    }

    if (!reporterExists) {
      const hashedPassword = await bcrypt.hash('reporter123', 10);
      await User.create({
        username: 'reporter',
        email: 'reporter@bugtracker.com',
        password: hashedPassword,
        role: 'reporter'
      });
      console.log('Default reporter user created');
    }
  } catch (error) {
    console.error('Error creating default users:', error);
  }
};

// Initialize default users
createDefaultUsers();

// Routes

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, role = 'reporter' } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      role
    });

    await user.save();

    res.status(201).json({ 
      message: 'User created successfully',
      user: { id: user._id, username: user.username, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Find user
    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Bugs (with role-based filtering)
app.get('/api/bugs', authenticateToken, async (req, res) => {
  try {
    const { status, severity, search } = req.query;
    let query = {};

    // Role-based filtering
    if (req.user.role === 'reporter') {
      query.reportedBy = req.user.userId;
    }

    // Status filter
    if (status && status !== 'all') {
      query.status = status;
    }

    // Severity filter
    if (severity && severity !== 'all') {
      query.severity = severity;
    }

    // Search by title
    if (search) {
      query.title = { $regex: search, $options: 'i' };
    }

    const bugs = await Bug.find(query)
      .populate('reportedBy', 'username email')
      .sort({ createdAt: -1 });

    res.json(bugs);
  } catch (error) {
    console.error('Get bugs error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Bug
app.post('/api/bugs', authenticateToken, async (req, res) => {
  try {
    const { title, description, severity } = req.body;

    if (!title || !description || !severity) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const bug = new Bug({
      title,
      description,
      severity,
      reportedBy: req.user.userId
    });

    await bug.save();
    await bug.populate('reportedBy', 'username email');

    res.status(201).json(bug);
  } catch (error) {
    console.error('Create bug error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Bug Status
app.put('/api/bugs/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const bugId = req.params.id;

    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }

    // Find the bug
    const bug = await Bug.findById(bugId);
    if (!bug) {
      return res.status(404).json({ error: 'Bug not found' });
    }

    // Check permissions
    if (req.user.role === 'reporter' && bug.reportedBy.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Update bug
    bug.status = status;
    bug.updatedAt = new Date();
    await bug.save();
    await bug.populate('reportedBy', 'username email');

    res.json(bug);
  } catch (error) {
    console.error('Update bug error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});