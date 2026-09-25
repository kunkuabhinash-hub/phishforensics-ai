const express = require('express');
const router = express.Router();
const analyzeController = require('../controllers/analyzeController');

// POST /api/analyze
router.post('/', analyzeController.analyzeContent);

// POST /api/analyze/unified
router.post('/unified', analyzeController.analyzeUnifiedContent);

module.exports = router;
