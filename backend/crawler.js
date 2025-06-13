const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const { addToSiteMap, getSiteMap } = require('./siteMapStore');

const MAX_CRAWL = 30; // Maximum number of URLs to crawl per session

async function crawl(url, baseDomain, depth = 0, maxDepth = 5) {
  // Stop if we've reached the crawl limit
  if (getSiteMap().length >= MAX_CRAWL) return;
  if (depth > maxDepth) return;
  if (getSiteMap().find(e => e.url === url)) return; // Prevent duplicate crawling

  try {
    console.log(`Crawling: ${url}`);
    const res = await axios.get(url);
    addToSiteMap({ url, method: 'GET', status: res.status });

    const $ = cheerio.load(res.data);
    const links = [];
    $('a[href]').each((_, el) => {
      let link = $(el).attr('href');
      if (!link) return;
      if (link.startsWith('#')) return;
      try {
        link = new URL(link, url).toString();
      } catch (e) {
        return;
      }
      if (!getSiteMap().find(e => e.url === link) && links.length + getSiteMap().length < MAX_CRAWL) {
        links.push(link);
      }
    });

    for (const link of links) {
      await crawl(link, baseDomain, depth + 1, maxDepth);
      if (getSiteMap().length >= MAX_CRAWL) break;
    }
  } catch (err) {
    console.log(`Error crawling ${url}:`, err.message);
    addToSiteMap({ url, method: 'GET', status: err.response ? err.response.status : 'ERR' });
  }
}

module.exports = { crawl };