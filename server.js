const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors'); // Import the cors package
const app = express();

app.use(express.json());
app.use(cors()); // Enable CORS for all routes

// Existing spider endpoint
app.post('/spider', async (req, res) => {
  const { url, maxDepth = 2, rateLimit = 1000, concurrency = 5 } = req.body;
  const visitedUrls = new Set();
  const results = [];
  const queue = [];

  async function crawl(url, depth) {
    if (depth > maxDepth || visitedUrls.has(url)) {
      return;
    }
    visitedUrls.add(url);

    try {
      const response = await axios.get(url);
      results.push({ url: response.config.url, status: response.status });

      const $ = cheerio.load(response.data);
      const links = $('a[href]').map((i, link) => $(link).attr('href')).get();

      for (const link of links) {
        const absoluteLink = new URL(link, url).href;

        // Ensure the link is internal
        if (absoluteLink.startsWith(url)) {
          queue.push({ url: absoluteLink, depth: depth + 1 });
        }
      }
    } catch (error) {
      console.error(`Failed to fetch ${url}:`, error.message);
    }
  }

  async function processQueue() {
    const promises = [];
    while (queue.length > 0 && promises.length < concurrency) {
      const { url, depth } = queue.shift();
      promises.push(crawl(url, depth));
      await new Promise(resolve => setTimeout(resolve, rateLimit)); // Rate limiting
    }
    await Promise.all(promises);
    if (queue.length > 0) {
      await processQueue();
    }
  }

  try {
    await crawl(url, 0);
    await processQueue();
    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: 'Failed to spider the URL' });
  }
});

// New scanner endpoint
app.post('/scanner', async (req, res) => {
  const { url, scanType = 'passive', customRules = [] } = req.body;
  const results = [];

  // Validate and parse the URL
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  async function passiveScan(url) {
    try {
      const response = await axios.get(url.href);
      const headers = response.headers;
      const body = response.data;

      // Check for missing security headers
      if (!headers['x-content-type-options']) {
        results.push({ url: url.href, issue: 'Missing X-Content-Type-Options header', severity: 'Medium' });
      }
      if (!headers['x-frame-options']) {
        results.push({ url: url.href, issue: 'Missing X-Frame-Options header', severity: 'Medium' });
      }
      if (!headers['content-security-policy']) {
        results.push({ url: url.href, issue: 'Missing Content-Security-Policy header', severity: 'High' });
      }

      // Check for information leaks
      if (body.includes('<!--')) {
        results.push({ url: url.href, issue: 'HTML comments found', severity: 'Low' });
      }

      // Add more passive checks as needed
    } catch (error) {
      if (error.response) {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: `Request failed with status code ${error.response.status}`, severity: 'High' });
      } else {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: 'Request failed', severity: 'High' });
      }
    }
  }

  async function activeScan(url) {
    try {
      // Implement active scanning logic here
      // Example: SQL Injection test
      const response = await axios.get(`${url.href}' OR '1'='1`);
      if (response.data.includes('SQL syntax')) {
        results.push({ url: url.href, issue: 'Possible SQL Injection', severity: 'High' });
      }

      // Add more active checks as needed
    } catch (error) {
      if (error.response) {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: `Request failed with status code ${error.response.status}`, severity: 'High' });
      } else {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: 'Request failed', severity: 'High' });
      }
    }
  }

  async function customRuleScan(url, rules) {
    try {
      const response = await axios.get(url.href);
      const body = response.data;

      rules.forEach(rule => {
        const regex = new RegExp(rule.pattern, 'i');
        if (regex.test(body)) {
          results.push({ url: url.href, issue: rule.description, severity: rule.severity });
        }
      });
    } catch (error) {
      if (error.response) {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: `Request failed with status code ${error.response.status}`, severity: 'High' });
      } else {
        console.error(`Failed to fetch ${url.href}:`, error.message);
        results.push({ url: url.href, issue: 'Request failed', severity: 'High' });
      }
    }
  }

  try {
    if (scanType === 'passive') {
      await passiveScan(parsedUrl);
    } else if (scanType === 'active') {
      await activeScan(parsedUrl);
    } else if (scanType === 'custom') {
      await customRuleScan(parsedUrl, customRules);
    }
    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: 'Failed to scan the URL' });
  }
});

app.listen(8080, () => {
  console.log('Proxy server is running on port 8080');
});