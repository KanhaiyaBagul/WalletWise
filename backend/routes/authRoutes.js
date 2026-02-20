const express = require('express');
const rateLimit = require('express-rate-limit');
const { protect } = require('../middleware/auth');
const validate = require('../middleware/validate');
const {
  userRegisterSchema,
  userLoginSchema,
  userUpdateSchema,
  verifyEmailSchema,
  resendOtpSchema,
  forgotPasswordRequestSchema,
  forgotPasswordVerifySchema,
  resetPasswordSchema
} = require('../utils/validationSchemas');
const authController = require('../controllers/authController');

const singleUpload = require('../middleware/multer');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many attempts. Please try again later.'
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  message: 'Too many attempts from this IP. Please try again in 5 minutes.'
});

router.post('/register', authLimiter, validate(userRegisterSchema), authController.register);
router.post('/login', authLimiter, validate(userLoginSchema), authController.login);
router.post('/verify-email', authLimiter, validate(verifyEmailSchema), authController.verifyEmail);
router.post('/resend-otp', authLimiter, validate(resendOtpSchema), authController.resendEmailOtp);
router.post('/forgot-password', authLimiter, authController.forgotPassword);
router.post('/reset-password', authLimiter, authController.resetPassword);
router.post('/logout', authController.logout);
router.post('/refresh', authController.refresh);
router.get('/me', protect, authController.me);
router.put('/profile', protect, singleUpload, validate(userUpdateSchema), authController.updateProfile);

module.exports = router;
