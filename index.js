


require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const jwt = require('jsonwebtoken');
const User = require('./models/User'); 
const cookieParser = require('cookie-parser');
const authMiddleware = require('./middleware/auth'); 
const nodemailer = require("nodemailer");
const Note = require('./models/Note'); // Note model


const app = express();

// middleware

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());

// API routes
app.post("/signup", async (req, res) => {
  console.log("Signup route hit");
  let { name, email, password , confirmPass } = req.body;
  console.log("Received data:", req.body);

  if (password !== confirmPass) {
      return res.status(400).json({ success: false, message: "Passwords do not match" });
    }

  if (!name || !email || !password || !confirmPass) {
    return res.status(400).json({ error: "Name, email, and password are required" });
  }

  try {
    let existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists with this email" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    let newUser = new User({ name, email, password: hashedPassword });
    const savedUser = await newUser.save();

    res.status(201).json({ message: "User registered!", userId: savedUser._id });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Signin data:", req.body);

    if (!email || !password) {
      return res.status(400).json({ error: "Missing email or password" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { email: user.email, userId: user._id },
      process.env.JWT_SECRET || "secret_jwt_key", // typo fixed
      { expiresIn: "1h" }
    );

    // set cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // change to true in production with HTTPS
      sameSite: "strict",
    });

    res.status(200).json({
      message: "Login successful",
      user: { id: user._id, email: user.email, name: user.name },
    });
  } catch (err) {
    console.error("Signin Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
app.get('/home', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});



// ✅ Route to return logged-in user info
app.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("name email");
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ name: user.name, email: user.email });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});


app.get('/himanshu', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

// serve frontend (AFTER routes)
app.use(express.static(path.join(__dirname, "public")));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});
app.get('/forget-password', (req, res) => {
  res.sendFile(path.join(__dirname, "views", "forget-password.html"));
});

app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "Email not registered" });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpire = Date.now() + 1000 * 60 * 5; // 5 minutes
    await user.save();

    // Send OTP (demo: console log, production: send via email)
    /* console.log(`OTP for ${email}: ${otp}`); */

    // Example email (optional)
    let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: "kp121005@gmail.com", pass: "wehqowlctezhjcbu" },
     });
    await transporter.sendMail({
    from: "kp121005@gmail.com",
    to: email,
    subject: "Password Reset OTP",
    text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({
      email,
      otp,
      otpExpire: { $gt: Date.now() } // must not be expired
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    res.json({ success: true, message: "OTP verified" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/reset-password", async (req, res) => {
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

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    // Clear OTP
    user.otp = undefined;
    user.otpExpire = undefined;

    await user.save();

    res.json({ success: true, message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  try {
    // If using JWT stored in cookie
    res.clearCookie("token"); 
    return res.status(200).json({ message: "Logged out successfully" });

    
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/create", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;

    const note = new Note({
      title,
      content,
      user: req.user.userId   // ✅ attach logged-in user
    });

    await note.save();
    res.status(201).json({ success: true, note });
  } catch (err) {
    console.error("Error creating note:", err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get("/notes", authMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user.userId }).sort({ createdAt: -1 });
    res.json(notes);
  } catch (err) {
    console.error("Error fetching notes:", err);
    res.status(500).json({ error: "Server error" });
  }
});



app.get("/notes/:id", authMiddleware, async (req, res) => {
  try {
    const note = await Note.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!note) return res.status(404).json({ error: "Note not found" });
    res.json(note);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});