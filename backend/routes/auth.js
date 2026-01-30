const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { body, validationResult } = require('express-validator');

// ==================== JWT MIDDLEWARE ====================

// Generate JWT Token
const generateToken = (user) => {
  return jwt.sign(
    { 
      userId: user._id, 
      email: user.email,
      studentId: user.studentId
    },
    process.env.JWT_SECRET || 'walletwise-secret-key-2024',
    { expiresIn: '7d' }
  );
};

// Verify Token Middleware
const verifyToken = (req, res, next) => {
  try {
    let token;
    
    // Check multiple sources for token
    // 1. Authorization header (Bearer token)
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }
    // 2. Cookie (for web frontend)
    else if (req.cookies && req.cookies.auth_token) {
      token = req.cookies.auth_token;
    }
    // 3. Query parameter (for testing)
    else if (req.query && req.query.token) {
      token = req.query.token;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'walletwise-secret-key-2024');
    
    // Attach user info to request
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    req.userStudentId = decoded.studentId;
    req.user = decoded;
    
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    
    // Clear invalid token cookie
    res.clearCookie('auth_token');
    
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token. Please login again.'
    });
  }
};

// ==================== AUTH ROUTES ====================

// Register/Signup
router.post('/register', [
  body('studentId').notEmpty().withMessage('Student ID is required').trim(),
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('fullName').notEmpty().withMessage('Full name is required').trim(),
  body('department').notEmpty().withMessage('Department is required').trim(),
  body('year').notEmpty().withMessage('Year is required')
], async (req, res) => {
  try {
    console.log('\n📝 REGISTRATION REQUEST');
    console.log('Request body:', req.body);
    
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { studentId, email, password, fullName, phoneNumber, department, year } = req.body;

    // Normalize inputs
    const normalizedStudentId = studentId.trim();
    const normalizedEmail = email.toLowerCase().trim();
    const normalizedName = fullName.trim();
    const normalizedDepartment = department.trim();
    const normalizedPhone = phoneNumber ? phoneNumber.trim() : '';

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [
        { email: normalizedEmail },
        { studentId: normalizedStudentId }
      ] 
    });
    
    if (existingUser) {
      let message = 'User already exists';
      if (existingUser.email === normalizedEmail && existingUser.studentId === normalizedStudentId) {
        message = `User with email "${existingUser.email}" and student ID "${existingUser.studentId}" already exists`;
      } else if (existingUser.email === normalizedEmail) {
        message = `User with email "${existingUser.email}" already exists`;
      } else if (existingUser.studentId === normalizedStudentId) {
        message = `User with student ID "${existingUser.studentId}" already exists`;
      }
      
      return res.status(400).json({
        success: false,
        message: message
      });
    }

    // Create new user
    const user = await User.create({
      studentId: normalizedStudentId,
      email: normalizedEmail,
      password: password,
      fullName: normalizedName,
      phoneNumber: normalizedPhone,
      department: normalizedDepartment,
      year: year,
      walletBalance: 0
    });

    console.log('✅ User created successfully:', user.email);

    // Generate token
    const token = generateToken(user);
    
    // Set HTTP-only cookie for web clients
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });

    // Return success response with token in body (for API clients)
    res.status(201).json({
      success: true,
      message: 'Registration successful!',
      token: token, // Return token in response for mobile/API clients
      user: {
        _id: user._id,
        studentId: user.studentId,
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        department: user.department,
        year: user.year,
        walletBalance: user.walletBalance
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    
    // Handle duplicate key errors
    if (error.code === 11000) {
      const duplicateField = Object.keys(error.keyPattern)[0];
      const duplicateValue = error.keyValue[duplicateField];
      const fieldName = duplicateField === 'studentId' ? 'Student ID' : 'Email';
      
      return res.status(400).json({
        success: false,
        message: `${fieldName} "${duplicateValue}" is already registered`
      });
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: messages.join(', ')
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

// Login
router.post('/login', [
  body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    console.log('\n🔐 LOGIN REQUEST');
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }

    const { email, password } = req.body;

    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();
    
    console.log('Attempting login for:', normalizedEmail);

    // Find user by email
    const user = await User.findOne({ email: normalizedEmail });
    
    if (!user) {
      console.log('❌ User not found:', normalizedEmail);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check password
    console.log('Checking password for user:', user.email);
    const isPasswordMatch = await user.comparePassword(password);
    
    if (!isPasswordMatch) {
      console.log('❌ Invalid password for user:', user.email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    console.log('✅ Login successful for:', user.email);
    
    // Generate token
    const token = generateToken(user);
    
    // Set HTTP-only cookie for web clients
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });

    // Return success response with token in body (for API clients)
    res.json({
      success: true,
      message: 'Login successful',
      token: token, // Return token in response for mobile/API clients
      user: {
        _id: user._id,
        studentId: user.studentId,
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        department: user.department,
        year: user.year,
        walletBalance: user.walletBalance
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// Logout
router.post('/logout', (req, res) => {
  try {
    console.log('🔓 LOGOUT REQUEST');
    
    // Clear the auth cookie
    res.clearCookie('auth_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
    
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Error during logout'
    });
  }
});

// Get current user profile (protected route)
router.get('/me', verifyToken, async (req, res) => {
  try {
    console.log('📋 GET USER PROFILE for:', req.userEmail);
    
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      console.log('❌ User not found for ID:', req.userId);
      res.clearCookie('auth_token');
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    console.log('✅ User profile retrieved:', user.email);
    
    res.json({
      success: true,
      user: user
    });
    
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching profile'
    });
  }
});

// Get user by ID (admin or self)
router.get('/:id', verifyToken, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Users can only view their own profile
    if (userId !== req.userId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this profile'
      });
    }
    
    const user = await User.findById(userId).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      user: user
    });
    
  } catch (error) {
    console.error('Get user by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update user profile (protected route)
router.put('/profile', verifyToken, async (req, res) => {
  try {
    const { fullName, phoneNumber, department, year } = req.body;
    
    // Find user
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Update fields if provided
    if (fullName) user.fullName = fullName.trim();
    if (phoneNumber) user.phoneNumber = phoneNumber.trim();
    if (department) user.department = department.trim();
    if (year) user.year = year;
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        _id: user._id,
        studentId: user.studentId,
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        department: user.department,
        year: user.year,
        walletBalance: user.walletBalance
      }
    });
    
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating profile'
    });
  }
});

// Update wallet balance (for transactions)
router.put('/wallet', verifyToken, async (req, res) => {
  try {
    const { amount, type } = req.body; // type: 'add' or 'subtract'
    
    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required'
      });
    }
    
    if (!['add', 'subtract'].includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Type must be "add" or "subtract"'
      });
    }
    
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    if (type === 'add') {
      user.walletBalance += amount;
    } else if (type === 'subtract') {
      if (user.walletBalance < amount) {
        return res.status(400).json({
          success: false,
          message: 'Insufficient wallet balance'
        });
      }
      user.walletBalance -= amount;
    }
    
    await user.save();
    
    res.json({
      success: true,
      message: `Wallet ${type === 'add' ? 'credited' : 'debited'} successfully`,
      walletBalance: user.walletBalance
    });
    
  } catch (error) {
    console.error('Update wallet error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error updating wallet'
    });
  }
});

// Health check for auth service
router.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'Authentication Service',
    status: 'Operational',
    timestamp: new Date().toISOString(),
    endpoints: {
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      logout: 'POST /api/auth/logout',
      profile: 'GET /api/auth/me (requires token)',
      getUser: 'GET /api/auth/:id (requires token)',
      updateProfile: 'PUT /api/auth/profile (requires token)',
      updateWallet: 'PUT /api/auth/wallet (requires token)'
    }
  });
});

// Export both router and verifyToken middleware
module.exports = {
  router,
  verifyToken
};