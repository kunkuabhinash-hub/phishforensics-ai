const express = require('express');
const cors = require('cors');
require('dotenv').config();

const analyzeRoutes = require('./routes/analyzeRoutes');
const investigationRoutes = require('./routes/investigationRoutes');
const errorHandler = require('./middleware/errorHandler');
const { initDatabase } = require('./db/database.ts');

// Initialize SQLite database & migrations on startup
try {
  initDatabase();
} catch (dbError) {
  console.error('[Startup Warning] Database initialization error:', dbError);
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Routes
app.use('/api/analyze', analyzeRoutes);
app.use('/api/investigations', investigationRoutes);

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'PhishForensics AI Backend is running'
  });
});

// Centralized Error Handling Middleware
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
