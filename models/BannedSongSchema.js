const mongoose = require('mongoose');

// --- DATABASE SCHEMA ---
// This defines the structure for the documents we will save
const BannedSongSchema = new mongoose.Schema({
  songName: {
    type: String,
    required: true
  },
  songId: {
    type: String,
    required: true
  },
  reportedAt: {
    type: Date,
    default: Date.now // Automatically sets the time when the report is created
  }
});

module.exports = mongoose.model('BannedSong', BannedSongSchema);

