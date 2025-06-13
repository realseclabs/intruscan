const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const scopeManager = require('./scopeManager');
const siteMapManager = require('./siteMapManager');
const { crawl } = require('./crawler');
const { clearSiteMap } = require('./siteMapStore');

const { scanAll } = require('./scanner');

const app = express();
const PORT = 4000;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/scope', scopeManager);
app.use('/api/sitemap', siteMapManager);

// Crawler endpoint
app.post('/api/crawl', async (req, res) => {
  const { startUrl } = req.body;
  if (!startUrl) return res.status(400).json({ error: 'Missing startUrl' });

  clearSiteMap();
  const baseDomain = new URL(startUrl).origin;
  await crawl(startUrl, baseDomain);

  res.json({ success: true });
});

app.post('/api/scan', async (req, res) => {
  const { startUrl } = req.body; // Accept startUrl from frontend
  const results = await scanAll(startUrl);
  res.json({ results });
});

// Health check
app.get('/', (req, res) => {
  res.send('Intruscan backend running!');
});

app.listen(PORT, () => {
  console.log(`Intruscan backend listening at http://localhost:${PORT}`);
});