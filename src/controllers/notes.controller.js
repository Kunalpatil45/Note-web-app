const Note = require('../models/Note');
const { encrypt, decrypt } = require('../services/encryption.service');

exports.createNote = async (req, res) => {
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
};

exports.getNotes = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `notes:${userId}`;

        const cached = cache.get(cacheKey);
        if (cached) {
            console.log("CACHE HIT",cached);
            return res.json(cached);
        }

        const notes = await Note.find({ user: req.user.userId }).sort({ createdAt: -1 });
        const decryptedNotes = notes.map(note => ({
            _id: note._id,
            title: note.title,
            content: decrypt(note.content),
            createdAt: note.createdAt,
        }));

        cache.set(cacheKey, decryptedNotes, 60000);
        console.log("Fetched from database...");

        res.json(decryptedNotes);
    } catch (err) {
        console.error("Error fetching notes:", err);
        res.status(500).json({ error: "Server error" });
    }
};

exports.getNoteById = async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if (!note || note.user !== req.user.userId) {
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
};

exports.updateNote = async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if (!note || note.user !== req.user.userId) {
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
};

exports.deleteNote = async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if (!note || note.user !== req.user.userId) {
            return res.status(404).json({ error: "Note not found" });
        }

        await Note.deleteOne({ _id: note._id });
        res.json({ message: "Note deleted" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server error" });
    }
};
