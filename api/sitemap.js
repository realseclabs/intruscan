import { URL } from 'url';

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