const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
    user: {
        type: String,      // User ID from generateUserId
        required: true
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Note', noteSchema);
