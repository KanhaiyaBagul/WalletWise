const bcrypt = require('bcryptjs');
const { z } = require('zod');
const User = require('../models/User');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken
} = require('../utils/tokens');

const registerSchema = z.object({
  studentId: z.string().trim().min(1, 'Student ID is required'),
  fullName: z.string().trim().min(1, 'Full name is required'),
  email: z.string().trim().email('Invalid email'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
  phoneNumber: z.string().trim().optional().or(z.literal('')),
  department: z.string().trim().min(1, 'Department is required'),
  year: z.enum(['1st', '2nd', '3rd', '4th', '5th'])
});

const loginSchema = z.object({
  email: z.string().trim().email('Invalid email'),
  password: z.string().min(1, 'Password is required')
});

const updateProfileSchema = z.object({
  fullName: z.string().trim().optional(),
  phoneNumber: z.string().trim().optional(),
  department: z.string().trim().optional(),
  year: z.enum(['1st', '2nd', '3rd', '4th', '5th']).optional()
});

const cookieOptions = () => {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/'
  };
};

const setAuthCookies = (res, accessToken, refreshToken) => {
  const accessMaxAge = 15 * 60 * 1000;
  const refreshMaxAge = 7 * 24 * 60 * 60 * 1000;

  res.cookie('access_token', accessToken, {
    ...cookieOptions(),
    maxAge: accessMaxAge
  });

  res.cookie('refresh_token', refreshToken, {
    ...cookieOptions(),
    maxAge: refreshMaxAge
  });
};

const clearAuthCookies = (res) => {
  res.clearCookie('access_token', cookieOptions());
  res.clearCookie('refresh_token', cookieOptions());
};

const safeUser = (user) => ({
  id: user._id,
  email: user.email,
  fullName: user.fullName,
  studentId: user.studentId,
  department: user.department,
  year: user.year,
  phoneNumber: user.phoneNumber,
  walletBalance: user.walletBalance,
  provider: user.provider
});

const register = async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: parsed.error.errors[0]?.message || 'Invalid input'
      });
    }

    const { studentId, fullName, email, password, phoneNumber, department, year } = parsed.data;

    const existing = await User.findOne({ $or: [{ email }, { studentId }] });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email or student ID'
      });
    }

    const user = new User({
      studentId,
      fullName,
      email,
      phoneNumber: phoneNumber || '',
      department,
      year,
      provider: 'local',
      walletBalance: 0
    });
    await user.setPassword(password);
    await user.save();

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await User.saveWithUniqueStudentId(user);

    setAuthCookies(res, accessToken, refreshToken);

    return res.status(201).json({
      success: true,
      message: 'Registration successful',
      user: safeUser(user)
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
};

const login = async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: parsed.error.errors[0]?.message || 'Invalid input'
      });
    }

    const { email, password } = parsed.data;
    const user = await User.findOne({ email });

    if (!user || !user.passwordHash) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await User.saveWithUniqueStudentId(user);

    setAuthCookies(res, accessToken, refreshToken);

    return res.json({
      success: true,
      message: 'Login successful',
      user: safeUser(user)
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
};

const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    if (refreshToken) {
      try {
        const decoded = verifyRefreshToken(refreshToken);
        const user = await User.findById(decoded.sub);
        if (user) {
          user.refreshTokenHash = null;
          await user.save();
        }
      } catch (error) {
        // ignore
      }
    }

    clearAuthCookies(res);
    return res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ success: false, message: 'Logout failed' });
  }
};

const refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) {
      return res.status(401).json({ success: false, message: 'Refresh token missing' });
    }

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.sub);

    if (!user || !user.refreshTokenHash) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const valid = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!valid) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, message: 'Refresh token revoked' });
    }

    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    user.refreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
    await user.save();

    setAuthCookies(res, newAccessToken, newRefreshToken);

    return res.json({ success: true, message: 'Session refreshed' });
  } catch (error) {
    console.error('Refresh error:', error);
    clearAuthCookies(res);
    return res.status(401).json({ success: false, message: 'Refresh failed' });
  }
};

const me = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    return res.json({ success: true, user: safeUser(user) });
  } catch (error) {
    console.error('Me error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

const updateProfile = async (req, res) => {
  try {
    const parsed = updateProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        message: parsed.error.errors[0]?.message || 'Invalid input'
      });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const { fullName, phoneNumber, department, year } = parsed.data;
    if (fullName !== undefined) user.fullName = fullName.trim();
    if (phoneNumber !== undefined) user.phoneNumber = phoneNumber.trim();
    if (department !== undefined) user.department = department.trim();
    if (year !== undefined) user.year = year;

    await user.save();

    return res.json({
      success: true,
      message: 'Profile updated successfully',
      user: safeUser(user)
    });
  } catch (error) {
    console.error('Update profile error:', error);
    return res.status(500).json({ success: false, message: 'Server error updating profile' });
  }
};

const googleCallback = async (req, res) => {
  try {
    const user = req.user;
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    user.refreshTokenHash = await bcrypt.hash(refreshToken, 10);
    await User.saveWithUniqueStudentId(user);

    setAuthCookies(res, accessToken, refreshToken);

    const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/dashboard`;
    return res.redirect(redirectUrl);
  } catch (error) {
    console.error('Google callback error:', error);
    return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}/login?error=google`);
  }
};

module.exports = {
  register,
  login,
  logout,
  refresh,
  me,
  updateProfile,
  googleCallback
};
