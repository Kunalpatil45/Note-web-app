const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const path = require('path');
const User = require('../models/User');
const generateUserId = require('../utils/generateUserId');

exports.signup = async (req, res) => {
    console.log("Signup route hit");
    let { name, email, password, confirmPass } = req.body;
    console.log("Received data:", req.body);

    if (!name || !email || !password || !confirmPass) {
        return res.status(400).json({ success: false, message: "Name, email, and password are required" });
    }

    if (password !== confirmPass) {
        return res.status(400).json({ success: false, message: "Passwords do not match" });
    }

    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (!strongPasswordRegex.test(password)) {
        return res.status(400).json({
            success: false,
            message: "Password must be strong. It should contain at least 8 characters, including uppercase, lowercase, number, and special character."
        });
    }

    try {
        let existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "User already exists with this email" });
        }

        const userId = await generateUserId(name);
        const hashedPassword = await bcrypt.hash(password, 8);

        let newUser = new User({ name, email, password: hashedPassword, userId });
        const savedUser = await newUser.save();

        res.status(201).json({
            success: true,
            message: "User registered!",
            userId: savedUser.userId
        });
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).json({ success: false, message: "Server error during signup" });
    }
};

exports.signin = async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid password" });

        const token = jwt.sign(
            { userId: user._id, name: user.name, email: user.email },
            process.env.JWT_SECRET || "secret_jwt_key",
            { expiresIn: "1d" }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
        });

        res.json({ message: "Login successful" });
    } catch (err) {
        console.error("Signin error:", err);
        res.status(500).json({ error: "Server error" });
    }
};

exports.getMe = async (req, res) => {
    try {
        res.json({
            name: req.user.name,
            email: req.user.email,
            userId: req.user.userId
        });
    } catch (err) {
        console.error("Error in /me:", err);
        res.status(500).json({ error: "Server error" });
    }
};

exports.sendOtp = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email required" });

        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpire = Date.now() + 1000 * 60 * 5;
        await user.save();

        let transporter = nodemailer.createTransport({
            service: "gmail",
            auth: { user: "kp121005@gmail.com", pass: "wehqowlctezhjcbu" },
        });

        await transporter.sendMail({
            from: "kp121005@gmail.com",
            to: email,
            subject: "Note Web App OTP",
            text: `Your OTP is ${otp}. It expires in 5 minutes.`,
        });

        res.json({ success: true, message: "OTP sent to email" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
};

exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({
            email,
            otp,
            otpExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        res.json({ success: true, message: "OTP verified" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({
            email,
            otp,
            otpExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired OTP" });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        user.otp = undefined;
        user.otpExpire = undefined;

        await user.save();

        res.json({ success: true, message: "Password reset successful" });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
};

exports.logout = (req, res) => {
    try {
        console.log("Logout route hit");
        res.clearCookie("token");
        res.redirect("/signup");
    } catch (err) {
        console.error("Logout error:", err);
        res.status(500).json({ error: "Something went wrong" });
    }
};

exports.renderIntro = (req, res) => {
    res.sendFile(path.join(__dirname, "../..", "public", "intro.html"));
};

exports.renderProfile = (req, res) => {
    res.sendFile(path.join(__dirname, "../..", "public", "profile.html"));
};

exports.renderMain = (req, res) => {
    res.sendFile(path.join(__dirname, "../..", "public", "main.html"));
};

exports.renderSignup = (req, res) => {
    res.sendFile(path.join(__dirname, "../..", "views", "signup.html"));
};

exports.renderForgetPassword = (req, res) => {
    res.sendFile(path.join(__dirname, "../..", "views", "forget-password.html"));
};
