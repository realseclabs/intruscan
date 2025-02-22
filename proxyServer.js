const http = require('http');
const https = require('https');
const httpProxy = require('http-proxy');
const url = require('url');
const WebSocket = require('ws');
const fs = require('fs');

const proxy = httpProxy.createProxyServer({
  ssl: {
    key: fs.readFileSync('proxy-key.pem', 'utf8'),
    cert: fs.readFileSync('proxy-cert.pem', 'utf8')
  },
  secure: false // This allows self-signed certificates
});

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  if (parsedUrl.pathname === '/start') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Proxy started');
  } else if (parsedUrl.pathname === '/stop') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Proxy stopped');
    server.close();
  } else {
    proxy.web(req, res, { target: req.url }, (err) => {
      if (err) {
        console.error('Proxy error:', err);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Proxy error');
      }
    });
  }
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  console.log('WebSocket connection established');
});

proxy.on('proxyReq', (proxyReq, req, res, options) => {
  console.log('Request:', req.method, req.url);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'request', method: req.method, url: req.url }));
    }
  });
});

proxy.on('proxyRes', (proxyRes, req, res) => {
  console.log('Response:', proxyRes.statusCode, req.url);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'response', statusCode: proxyRes.statusCode, url: req.url }));
    }
  });
});

server.listen(8080, () => {
  console.log('Proxy server is running on port 8080');
});