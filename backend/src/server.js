const express = require('express');
const cors = require('cors');
require('dotenv').config();

const analyzeRoutes = require('./routes/analyzeRoutes');
const errorHandler = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/analyze', analyzeRoutes);

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
