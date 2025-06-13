const express = require('express');
const router = express.Router();
const { getSiteMap, addToSiteMap, clearSiteMap } = require('./siteMapStore');

// Get the current site map
router.get('/', (req, res) => {
  res.json(getSiteMap());
});

// Add a new entry to the site map
router.post('/add', (req, res) => {
  const { url, method, status } = req.body;
  if (!url || !method || !status) {
    return res.status(400).json({ error: 'Missing url, method, or status' });
  }
  addToSiteMap({ url, method, status });
  res.json({ success: true, siteMap: getSiteMap() });
});

// Clear the site map
router.post('/clear', (req, res) => {
  clearSiteMap();
  res.json({ success: true });
});

module.exports = router;