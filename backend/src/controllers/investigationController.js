const { listInvestigations, getInvestigation, deleteInvestigation } = require('../db/investigationRepository.ts');
const AppError = require('../utils/AppError');

/**
 * Controller for retrieving and managing persisted investigations.
 */

// GET /api/investigations
const handleListInvestigations = async (req, res, next) => {
  try {
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

    const investigations = listInvestigations(limit, offset);
    return res.status(200).json({
      success: true,
      count: investigations.length,
      investigations
    });
  } catch (error) {
    console.error('[InvestigationController] Error listing investigations:', error);
    next(new AppError('Failed to retrieve investigation history from database.', 500));
  }
};

// GET /api/investigations/:analysisId
const handleGetInvestigation = async (req, res, next) => {
  const { analysisId } = req.params;

  try {
    if (!analysisId || typeof analysisId !== 'string') {
      return next(new AppError('A valid analysisId parameter is required.', 400));
    }

    const investigation = getInvestigation(analysisId.trim());
    if (!investigation) {
      return next(new AppError(`Investigation not found with ID: ${analysisId}`, 404, analysisId));
    }

    return res.status(200).json(investigation);
  } catch (error) {
    console.error(`[InvestigationController] Error fetching investigation ${analysisId}:`, error);
    next(new AppError('Failed to fetch investigation record.', 500, analysisId));
  }
};

// DELETE /api/investigations/:analysisId
const handleDeleteInvestigation = async (req, res, next) => {
  const { analysisId } = req.params;

  try {
    if (!analysisId || typeof analysisId !== 'string') {
      return next(new AppError('A valid analysisId parameter is required.', 400));
    }

    const deleted = deleteInvestigation(analysisId.trim());
    if (!deleted) {
      return next(new AppError(`Investigation not found with ID: ${analysisId}`, 404, analysisId));
    }

    return res.status(200).json({
      success: true,
      message: 'Investigation deleted successfully',
      analysisId
    });
  } catch (error) {
    console.error(`[InvestigationController] Error deleting investigation ${analysisId}:`, error);
    next(new AppError('Failed to delete investigation from database.', 500, analysisId));
  }
};

module.exports = {
  handleListInvestigations,
  handleGetInvestigation,
  handleDeleteInvestigation
};
