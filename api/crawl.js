export default async function handler(req, res) {
  const { url } = req.query;
  if (!url) {
    res.status(400).json({ error: 'Missing url parameter' });
    return;
  }
  try {
    const response = await fetch(url, { method: 'GET' });
    const html = await response.text();
    res.status(200).json({ html });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch URL' });
  }
}