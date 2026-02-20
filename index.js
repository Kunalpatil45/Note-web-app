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
const Note = require('./models/Note'); 
const crypto = require('crypto'); 


const algorithm = "aes-256-cbc";
const secretKey = process.env.ENCRYPTION_KEY

const app = express();



app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());


async function generateUserId(name) {
  
  let base = name.split(" ")[0].toLowerCase().replace(/[^a-z0-9]/g, "");
  let userId;
  let isUnique = false;

  while (!isUnique) {
  
    const randomNum = Math.floor(100 + Math.random() * 900);
    userId = `${base}${randomNum}`;

    
    const existingUser = await User.findOne({ userId });
    if (!existingUser) {
      isUnique = true;
    }
  }
  return userId;
}

function encrypt(text) {
  const iv = crypto.randomBytes(16); 
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted; 
}

function decrypt(text) {
  const [ivHex, encryptedText] = text.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}





app.post("/signup", async (req, res) => {
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
      message:
        "Password must be strong. It should contain at least 8 characters, including uppercase, lowercase, number, and special character."
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
});



/* app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

  
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    
    const token = jwt.sign(
      { userId: user._id, name: user.name },
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
});
 */

app.post("/signin", async (req, res) => {
  try {
    console.time("TOTAL_LOGIN");

    const { email, password } = req.body;

    console.time("DB_LOOKUP");
    const user = await User.findOne({ email });
    console.timeEnd("DB_LOOKUP");

    if (!user) return res.status(400).json({ error: "User not found" });

    console.time("BCRYPT_COMPARE");
    const isMatch = await bcrypt.compare(password, user.password);
    console.timeEnd("BCRYPT_COMPARE");

    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    console.time("JWT_SIGN");
    const token = jwt.sign(
      { userId: user._id, name: user.name },
      process.env.JWT_SECRET || "secret_jwt_key",
      { expiresIn: "1d" }
    );
    console.timeEnd("JWT_SIGN");

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
    });

    console.timeEnd("TOTAL_LOGIN");

    res.json({ message: "Login successful" });

  } catch (err) {
    console.error("Signin error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "intro.html"));
});

app.get('/profile', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get('/create-note', authMiddleware, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main.html"));
});



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

    
    if (!otpStore[user._id] || otpStore[user._id] !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    
    const hashedPwd = await bcrypt.hash(newPassword, 10);
    user.password = hashedPwd;
    await user.save();

   
    delete otpStore[user._id];

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/send-otp', async (req, res) => {
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
      subject: "Note Web App OTP for Password Change",
      text: `Your OTP for Reseting Password is ${otp}. It expires in 5 minutes.`,
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

   
    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }
    if (user.otpExpire < Date.now()) {
      return res.status(400).json({ message: 'OTP expired' });
    }

   
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    
    user.otp = null;
    user.otpExpire = null;

    await user.save();

    res.json({ success: true, message: 'Password changed successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});







app.use(express.static(path.join(__dirname, "public")));
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});

app.get('/songs', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "songs.html"));
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
      otpExpire: { $gt: Date.now() }
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

    
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    
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

    const encryptedContent = encrypt(content);

    const newNote = new Note({
      title,
      content: encryptedContent,
      user: req.user.userId,
    });

    await newNote.save();

    res.json({
      _id: newNote._id,
      title: newNote.title,
      content: content, 
      createdAt: newNote.createdAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});




app.get("/notes", authMiddleware, async (req, res) => {
  try {
    const notes = await Note.find({ user: req.user.userId }).sort({ createdAt: -1 });

    
    const decryptedNotes = notes.map(note => ({
      _id: note._id,
      title: note.title,
      content: decrypt(note.content),
      createdAt: note.createdAt,
    }));

    res.json(decryptedNotes);
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

    res.json({
      _id: note._id,
      title: note.title,
      content: decrypt(note.content),
      createdAt: note.createdAt,
    });
  } catch (err) {
    console.error("Error fetching note:", err);
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
    if (content) note.content = encrypt(content); 

    await note.save();

    res.json({
      _id: note._id,
      title: note.title,
      content: decrypt(note.content),
      createdAt: note.createdAt,
    });
  } catch (err) {
    console.error("Error updating note:", err);
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