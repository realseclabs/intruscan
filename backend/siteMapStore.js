let siteMap = [];

function addToSiteMap(entry) {
  // Only add if not already present
  if (!siteMap.find(e => e.url === entry.url && e.method === entry.method)) {
    siteMap.push(entry);
  }
}

function clearSiteMap() {
  siteMap = [];
}

function getSiteMap() {
  return siteMap;
}

module.exports = { siteMap, addToSiteMap, clearSiteMap, getSiteMap };