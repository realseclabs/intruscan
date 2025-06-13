import { URL } from 'url';

let sitemap = [
  { url: '/login', method: 'POST', status: 302 },
  { url: '/dashboard', method: 'GET', status: 200 }
];

export function generateSitemap(crawledData) {
    const sitemap = {};

    crawledData.forEach(({ url, method, statusCode }) => {
        const parsedUrl = new URL(url);
        const path = parsedUrl.pathname;

        if (!sitemap[path]) {
            sitemap[path] = {
                methods: new Set(),
                statusCodes: new Set(),
            };
        }

        sitemap[path].methods.add(method);
        sitemap[path].statusCodes.add(statusCode);
    });

    // Convert sets to arrays for easier consumption
    for (const path in sitemap) {
        sitemap[path].methods = Array.from(sitemap[path].methods);
        sitemap[path].statusCodes = Array.from(sitemap[path].statusCodes);
    }

    return sitemap;
}

export default async function handler(req, res) {
  if (req.method === 'GET') {
    res.status(200).json(sitemap);
  } else if (req.method === 'POST') {
    const { url, method, status } = req.body;
    if (url && method && status) {
      sitemap.push({ url, method, status });
      res.status(200).json({ success: true });
    } else {
      res.status(400).json({ error: 'Missing fields' });
    }
  } else if (req.method === 'DELETE') {
    sitemap = [];
    res.status(200).json({ success: true });
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}