const express = require('express');
const router = express.Router();

let scope = {
  include: [],
  exclude: []
};

// Get current scope
router.get('/', (req, res) => {
  res.json(scope);
});

// Add a URL to include/exclude
router.post('/add', (req, res) => {
  const { type, url } = req.body;
  if (!url || (type !== 'include' && type !== 'exclude')) {
    return res.status(400).json({ error: 'Invalid type or url' });
  }
  if (!scope[type].includes(url)) {
    scope[type].push(url);
  }
  res.json({ success: true, scope });
});

// Remove a URL from include/exclude
router.post('/remove', (req, res) => {
  const { type, url } = req.body;
  if (!url || (type !== 'include' && type !== 'exclude')) {
    return res.status(400).json({ error: 'Invalid type or url' });
  }
  scope[type] = scope[type].filter(u => u !== url);
  res.json({ success: true, scope });
});

module.exports = router;