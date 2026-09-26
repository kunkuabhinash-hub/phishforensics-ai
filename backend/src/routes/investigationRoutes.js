const express = require('express');
const router = express.Router();
const {
  handleListInvestigations,
  handleGetInvestigation,
  handleDeleteInvestigation
} = require('../controllers/investigationController');

// GET /api/investigations - list previous investigations
router.get('/', handleListInvestigations);

// GET /api/investigations/:analysisId - retrieve complete unified contract
router.get('/:analysisId', handleGetInvestigation);

// DELETE /api/investigations/:analysisId - delete an investigation
router.delete('/:analysisId', handleDeleteInvestigation);

module.exports = router;
