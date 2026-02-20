const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const authRoutes = require('./routes/auth.routes');
const notesRoutes = require('./routes/notes.routes');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, "..", "public")));

// Mount routes
app.use(authRoutes);
app.use(notesRoutes);

module.exports = app;
