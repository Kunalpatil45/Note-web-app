const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../middleware/auth');
const authLimiter = require('../middleware/rateLimiter');

router.post("/signup", authLimiter, authController.signup);
router.post("/signin", authLimiter, authController.signin);
router.get("/me", authMiddleware, authController.getMe);
router.post('/send-otp', authController.sendOtp);
router.post("/verify-otp", authController.verifyOtp);
router.post("/reset-password", authController.resetPassword);
router.get("/logout", authController.logout);

// Page routes
router.get('/', authController.renderIntro);
router.get('/profile', authMiddleware, authController.renderProfile);
router.get('/create-note', authMiddleware, authController.renderMain);
router.get('/signup', authController.renderSignup);
router.get('/forget-password', authController.renderForgetPassword);
router.post("/api/forgot-password", authController.sendOtp); // Alias in index.js

module.exports = router;
