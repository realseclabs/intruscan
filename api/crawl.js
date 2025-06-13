export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  try {
    const { startUrl } = req.body;
    if (!startUrl) {
      res.status(400).json({ error: 'Missing startUrl' });
      return;
    }
    res.status(200).json({
      links: [
        { url: startUrl, method: 'GET', status: 200 },
        { url: startUrl + '/login', method: 'POST', status: 302 },
        { url: startUrl + '/dashboard', method: 'GET', status: 200 }
      ]
    });
  } catch (err) {
    res.status(500).json({ error: 'Crawl failed' });
  }
}