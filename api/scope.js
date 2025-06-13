class ScopeManager {
    constructor() {
        this.domains = new Set();
    }

    addDomain(domain) {
        if (this.isValidDomain(domain)) {
            this.domains.add(domain);
        } else {
            throw new Error('Invalid domain format');
        }
    }

    removeDomain(domain) {
        this.domains.delete(domain);
    }

    isValidDomain(domain) {
        const domainRegex = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}$/i;
        return domainRegex.test(domain);
    }

    getDomains() {
        return Array.from(this.domains);
    }
}

let scope = {
  include: [],
  exclude: []
};

export default async function handler(req, res) {
  if (req.method === 'GET') {
    res.status(200).json(scope);
  } else if (req.method === 'POST') {
    const { type, url } = req.body;
    if (!type || !url) {
      res.status(400).json({ error: 'Missing type or url' });
      return;
    }
    if (type === 'include' && !scope.include.includes(url)) {
      scope.include.push(url);
    }
    if (type === 'exclude' && !scope.exclude.includes(url)) {
      scope.exclude.push(url);
    }
    res.status(200).json(scope);
  } else if (req.method === 'DELETE') {
    const { type, url } = req.body;
    if (!type || !url) {
      res.status(400).json({ error: 'Missing type or url' });
      return;
    }
    if (type === 'include') {
      scope.include = scope.include.filter(u => u !== url);
    }
    if (type === 'exclude') {
      scope.exclude = scope.exclude.filter(u => u !== url);
    }
    res.status(200).json(scope);
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}