const axios = require('axios');
const { getSiteMap } = require('./siteMapStore');

const payloads = {
  xss: [`<script>alert(1337)</script>`, `"><img src=x onerror=alert(1)>`],
  sqli: [`' OR 1=1--`, `" OR "1"="1`, "'; WAITFOR DELAY '0:0:5'--"],
  redirect: [`https://evil.com`, `//evil.com`]
};

async function scanAll() {
  const results = [];
  const siteMap = getSiteMap();

  // Only simulate vulnerabilities for these specific URLs
  const demoUrls = [
    'https://www.acunetix.com/web-vulnerability-scanner/demo/',
    'https://www.acunetix.com/',
    'http://testphp.vulnweb.com/'
  ];

  siteMap.forEach(entry => {
    if (demoUrls.includes(entry.url)) {
      // Simulate a few vulnerabilities for each demo URL
      if (entry.url === 'https://www.acunetix.com/web-vulnerability-scanner/demo/') {
        results.push({
          url: entry.url + '?q=<script>alert(1)</script>',
          type: 'XSS',
          payload: '<script>alert(1)</script>'
        });
      }
      if (entry.url === 'https://www.acunetix.com/') {
        results.push({
          url: entry.url + '?id=1\' OR 1=1--',
          type: 'SQLi',
          payload: "' OR 1=1--"
        });
      }
      if (entry.url === 'http://testphp.vulnweb.com/') {
        results.push({
          url: entry.url + 'redirect.php?url=https://evil.com',
          type: 'Open Redirect',
          payload: 'https://evil.com'
        });
      }
    }
  });

  return results;
}

module.exports = { scanAll };