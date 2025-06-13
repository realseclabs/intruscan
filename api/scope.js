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

export default ScopeManager;