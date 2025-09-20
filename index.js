


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
async function generateUserId(name) {
  // Take lowercase, remove spaces/special chars
  let base = name.split(" ")[0].toLowerCase().replace(/[^a-z0-9]/g, "");
  let userId;
  let isUnique = false;

  while (!isUnique) {
    // Add a random 3-digit number
    const randomNum = Math.floor(100 + Math.random() * 900);
    userId = `${base}${randomNum}`;

    // Check if userId already exists
    const existingUser = await User.findOne({ userId });
    if (!existingUser) {
      isUnique = true;
    }
  }
  return userId;
}

app.post("/signup", async (req, res) => {
  console.log("Signup route hit");
  let { name, email, password, confirmPass } = req.body;
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

    // Generate unique userId based on name
    const userId = await generateUserId(name);

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save new user
    let newUser = new User({ name, email, password: hashedPassword, userId });
    const savedUser = await newUser.save();

    res.status(201).json({ 
      success: true,
      message: "User registered!",
      userId: savedUser.userId   // send generated userId
    });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Find user
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    // 2. Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    // 3. Create token
    const token = jwt.sign(
      { userId: user._id, name: user.name },
      process.env.JWT_SECRET || "secret_jwt_key",
      { expiresIn: "1d" }
    );

    // 4. Save token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false, // set true only in production with https
      sameSite: "lax",
    });

    // 5. Send response
    res.json({ message: "Login successful" });
  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


app.get('/', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "intro.html"));
});

app.get('/profile', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get('/create-note', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});


// ✅ Route to return logged-in user info
app.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("name email userId"); 
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ 
      name: user.name, 
      email: user.email, 
      userId: user.userId 
    });
  } catch (err) {
    console.error("Error in /me:", err);
    res.status(500).json({ error: "Server error" });
  }
});



app.post('/change-password', authMiddleware, async (req, res) => {
  try {
    const { otp, newPassword } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Verify OTP
    if (!otpStore[user._id] || otpStore[user._id] !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Hash new password
    const hashedPwd = await bcrypt.hash(newPassword, 10);
    user.password = hashedPwd;
    await user.save();

    // Remove OTP
    delete otpStore[user._id];

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Send OTP for password change
app.post('/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpire = Date.now() + 1000 * 60 * 5; // 5 minutes
    await user.save();

    
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: "kp121005@gmail.com", pass: "wehqowlctezhjcbu" },
    });

    await transporter.sendMail({
      from: "kp121005@gmail.com",
      to: email,
      subject: "OTP for Password Change",
      text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    });

    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});




app.post('/reset-password', async (req, res) => {
  console.log("Change password route hit");
  console.log(req.body);
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'Email, OTP, and new password required' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User  not found' });

    // Check OTP validity
    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }
    if (user.otpExpire < Date.now()) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Clear OTP fields
    user.otp = null;
    user.otpExpire = null;

    await user.save();

    res.json({ success: true, message: 'Password changed successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});






// serve frontend (AFTER routes)
app.use(express.static(path.join(__dirname, "public")));
app.get('/signup', (req, res) => {
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

app.get("/logout", (req, res) => {
  try {
    console.log("Logout route hit");
    res.clearCookie("token"); 
    
    res.redirect("/signup");

    
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});

app.post("/create", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;
    const newNote = new Note({
      title,
      content,
      user: req.user.userId,
    });
    await newNote.save();
    res.json({
      _id: newNote._id,
      title: newNote.title,
      content: newNote.content,
      createdAt: newNote.createdAt, // send created date
    });
  } catch (err) {
    console.error(err);
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

app.get("/note/:id", authMiddleware, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note || note.user.toString() !== req.user.userId) {
      return res.status(404).json({ error: "Note not found" });
    }
    res.json(note);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/note/:id", authMiddleware, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note || note.user.toString() !== req.user.userId) {
      return res.status(404).json({ error: "Note not found" });
    }

    const { title, content } = req.body;
    if (title) note.title = title;
    if (content) note.content = content;

    await note.save();
    res.json(note);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


app.delete("/note/:id", authMiddleware, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    if (!note || note.user.toString() !== req.user.userId) {
      return res.status(404).json({ error: "Note not found" });
    }

    await Note.deleteOne({ _id: note._id });

    res.json({ message: "Note deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});