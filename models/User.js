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
    otp: String,
  otpExpire: Date
});

module.exports = mongoose.model('User', userSchema);