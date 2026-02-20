const express = require('express');
const router = express.Router();
const notesController = require('../controllers/notes.controller');
const authMiddleware = require('../middleware/auth');

router.use(authMiddleware);

router.post("/create", notesController.createNote);
router.get("/notes", notesController.getNotes);
router.get("/note/:id", notesController.getNoteById);
router.put("/note/:id", notesController.updateNote);
router.delete("/note/:id", notesController.deleteNote);

module.exports = router;
