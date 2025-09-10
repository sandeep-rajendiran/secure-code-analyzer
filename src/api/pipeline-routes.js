const express = require('express');
const router = express.Router();

// Placeholder routes for CI/CD pipeline
router.get('/', (req, res) => {
  res.json({ message: 'Pipeline API endpoints' });
});

module.exports = router;