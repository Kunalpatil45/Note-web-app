require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    userId: {
        type: String,
        unique: true,
        required: true
    },
    otp: String,
    otpExpire: Date
});

// Pre-save hook to generate userId automatically
userSchema.pre("save", async function (next) {
    if (!this.isNew) return next();

    // Take username, lowercase, remove spaces, and add 4-digit random number
    const baseId = this.name.toLowerCase().replace(/\s+/g, "");
    const randomNum = Math.floor(1000 + Math.random() * 9000); // 4-digit number
    this.userId = `${baseId}${randomNum}`;

    // Ensure uniqueness
    const existingUser = await mongoose.model("User").findOne({ userId: this.userId });
    if (existingUser) {
        this.userId = `${baseId}${Date.now().toString().slice(-4)}`; // fallback
    }

    next();
});

module.exports = mongoose.model('User', userSchema);
