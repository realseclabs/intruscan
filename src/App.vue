<template>
  <div>
    <nav class="bg-gray-800 border-b border-gray-700">
      <div class="max-w-7xl mx-auto px-4">
        <div class="flex items-center justify-between h-16">
          <div class="flex items-center">
            <i class="bi bi-shield-lock text-2xl text-blue-500 mr-2"></i>
            <span class="font-bold text-xl">Intruscan</span>
          </div>
          <div class="flex space-x-4">
            <button v-for="tab in ['proxy', 'spider', 'scanner']" :key="tab" @click="activeTab = tab"
              :class="{'text-blue-500': activeTab === tab}"
              class="px-3 py-2 rounded-md text-sm font-medium hover:bg-gray-700 capitalize">
              {{ tab }}
            </button>
          </div>
        </div>
      </div>
    </nav>
    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 py-8">
      <!-- Proxy Tab -->
      <div v-if="activeTab === 'proxy'" class="space-y-6">
        <!-- Existing Proxy Tab Content -->
        <!-- Control Panel -->
        <div class="bg-gray-800 p-6 rounded-lg">
          <div class="flex items-center justify-between mb-6">
            <h2 class="text-xl font-semibold">HTTP Proxy Control</h2>
            <div class="flex items-center space-x-4">
              <span class="flex items-center">
                <span class="w-3 h-3 rounded-full mr-2" :class="isProxyRunning ? 'bg-green-500' : 'bg-red-500'">
                </span>
                {{ isProxyRunning ? 'Running' : 'Stopped' }}
              </span>
              <button @click="toggleProxy"
                :class="isProxyRunning ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'"
                class="px-4 py-2 rounded">
                {{ isProxyRunning ? 'Stop Proxy' : 'Start Proxy' }}
              </button>
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <label class="block text-sm font-medium mb-2">Proxy Port</label>
              <input type="number" v-model="proxyPort" class="bg-gray-700 rounded px-3 py-2 w-full">
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Filter Domain</label>
              <input type="text" v-model="filterDomain" placeholder="example.com"
                class="bg-gray-700 rounded px-3 py-2 w-full">
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Filter Method</label>
              <select v-model="filterMethod" class="bg-gray-700 rounded px-3 py-2 w-full">
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
          </div>

          <div class="mt-6">
            <h3 class="text-sm font-medium mb-2">SSL Certificate</h3>
            <div class="flex items-center justify-between bg-gray-700 p-4 rounded">
              <div class="flex items-center">
                <i class="bi bi-shield-check text-green-500 text-xl mr-2"></i>
                <span>CA Certificate Status: {{ isCertInstalled ? 'Installed' : 'Not Installed' }}</span>
              </div>
              <button @click="generateCert" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-sm">
                Generate New Certificate
              </button>
            </div>
          </div>
        </div>

        <!-- Intercepted Requests -->
        <div class="bg-gray-800 p-6 rounded-lg">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold">Intercepted Requests</h3>
            <div class="flex space-x-2">
              <button @click="clearRequests" class="px-3 py-1 text-sm bg-gray-700 hover:bg-gray-600 rounded">
                Clear All
              </button>
              <button @click="toggleInterception"
                :class="isInterceptionEnabled ? 'bg-red-600 hover:bg-red-700' : 'bg-blue-600 hover:bg-blue-700'"
                class="px-3 py-1 text-sm rounded">
                {{ isInterceptionEnabled ? 'Disable' : 'Enable' }} Interception
              </button>
            </div>
          </div>

          <div class="h-96 overflow-y-auto custom-scrollbar">
            <div v-for="(req, index) in filteredRequests" :key="index"
              class="border-b border-gray-700 p-4 hover:bg-gray-700 cursor-pointer" @click="editRequest(req)">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                  <span :class="{
                       'text-green-500': req.method === 'GET',
                       'text-blue-500': req.method === 'POST',
                       'text-yellow-500': req.method === 'PUT',
                       'text-red-500': req.method === 'DELETE'
                     }" class="font-mono font-bold">{{ req.method }}</span>
                  <span :class="{'text-red-400': req.status >= 400, 'text-green-400': req.status < 400}"
                    class="text-sm">
                    {{ req.status }}
                  </span>
                </div>
                <span class="text-sm text-gray-400">{{ req.timestamp }}</span>
              </div>
              <div class="font-mono text-sm mt-2 truncate">{{ req.url }}</div>
              <div class="flex items-center space-x-2 mt-2 text-sm text-gray-400">
                <span v-if="req.contentType">{{ req.contentType }}</span>
                <span v-if="req.size">{{ req.size }} bytes</span>
              </div>
            </div>
          </div>
        </div>
      </div>

     <!-- filepath: /c:/Users/Hp/Downloads/git_project_wide-canvas-m7epa227-61i97oea_ewfrz8/src/App.vue -->
<!-- Spider Tab -->
<div v-if="activeTab === 'spider'" class="space-y-6">
  <!-- Spider Control Panel -->
  <div class="bg-gray-800 p-6 rounded-lg">
    <div class="flex items-center justify-between mb-6">
      <h2 class="text-xl font-semibold">Spider Control</h2>
      <button @click="startSpider" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
        Start Spider
      </button>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div>
        <label class="block text-sm font-medium mb-2">Start URL</label>
        <input type="text" v-model="spiderStartUrl" placeholder="https://example.com"
          class="bg-gray-700 rounded px-3 py-2 w-full">
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Max Depth</label>
        <input type="number" v-model="spiderMaxDepth" placeholder="2"
          class="bg-gray-700 rounded px-3 py-2 w-full">
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Rate Limit (ms)</label>
        <input type="number" v-model="spiderRateLimit" placeholder="1000"
          class="bg-gray-700 rounded px-3 py-2 w-full">
      </div>
    </div>
  </div>

  <!-- Spider Results -->
  <div class="bg-gray-800 p-6 rounded-lg">
    <h3 class="text-lg font-semibold mb-4">Spider Results</h3>
    <div class="h-96 overflow-y-auto custom-scrollbar">
      <div v-for="(result, index) in spiderResults" :key="index"
        class="border-b border-gray-700 p-4 hover:bg-gray-700 cursor-pointer">
        <div class="font-mono text-sm mt-2 truncate">{{ result.url }}</div>
        <div class="text-sm text-gray-400">{{ result.status }}</div>
      </div>
    </div>
  </div>
</div>
<!-- Scanner Tab -->
<div v-if="activeTab === 'scanner'" class="space-y-6">
      <!-- Scanner Control Panel -->
      <div class="bg-gray-800 p-6 rounded-lg">
        <div class="flex items-center justify-between mb-6">
          <h2 class="text-xl font-semibold">Scanner Control</h2>
          <button @click="startScanner" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
            Start Scanner
          </button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label class="block text-sm font-medium mb-2">Target URL</label>
            <input type="text" v-model="scannerTargetUrl" placeholder="https://example.com"
              class="bg-gray-700 rounded px-3 py-2 w-full">
          </div>
          <div>
            <label class="block text-sm font-medium mb-2">Scan Type</label>
            <select v-model="scannerScanType" class="bg-gray-700 rounded px-3 py-2 w-full">
              <option value="passive">Passive</option>
              <option value="active">Active</option>
              <option value="custom">Custom</option>
            </select>
          </div>
        </div>
      </div>
      <!-- Scanner Results -->
      <div class="bg-gray-800 p-6 rounded-lg">
        <h3 class="text-lg font-semibold mb-4">Scanner Results</h3>
        <div class="h-96 overflow-y-auto custom-scrollbar">
          <div v-for="(result, index) in scannerResults" :key="index"
            class="border-b border-gray-700 p-4 hover:bg-gray-700 cursor-pointer">
            <div class="font-mono text-sm mt-2 truncate">{{ result.url }}</div>
            <div class="text-sm text-gray-400">{{ result.issue }} - {{ result.severity }}</div>
          </div>
        </div>
      </div>
    </div>

      <!-- Request Editor Modal -->
      <div v-if="showRequestEditor" class="fixed inset-0 flex items-center justify-center z-50">
        <div class="modal-overlay absolute inset-0" @click="showRequestEditor = false"></div>
        <div class="bg-gray-800 w-full max-w-4xl mx-4 rounded-lg shadow-xl z-10">
          <div class="p-6">
            <div class="flex justify-between items-center mb-4">
              <h3 class="text-lg font-semibold">Edit Request</h3>
              <button @click="showRequestEditor = false" class="text-gray-400 hover:text-white">
                <i class="bi bi-x-lg"></i>
              </button>
            </div>

            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium mb-2">Method</label>
                <select v-model="selectedRequest.method" class="bg-gray-700 rounded px-3 py-2 w-full">
                  <option v-for="method in ['GET', 'POST', 'PUT', 'DELETE']" :key="method">
                    {{ method }}
                  </option>
                </select>
              </div>

              <div>
                <label class="block text-sm font-medium mb-2">URL</label>
                <input type="text" v-model="selectedRequest.url" class="bg-gray-700 rounded px-3 py-2 w-full">
              </div>

              <div>
                <label class="block text-sm font-medium mb-2">Headers</label>
                <textarea v-model="selectedRequest.headers" rows="4"
                  class="bg-gray-700 rounded px-3 py-2 w-full font-mono text-sm"></textarea>
              </div>

              <div>
                <label class="block text-sm font-medium mb-2">Body</label>
                <textarea v-model="selectedRequest.body" rows="6"
                  class="bg-gray-700 rounded px-3 py-2 w-full font-mono text-sm"></textarea>
              </div>
            </div>

            <div class="flex justify-end space-x-3 mt-6">
              <button @click="dropRequest" class="px-4 py-2 bg-red-600 hover:bg-red-700 rounded">
                Drop
              </button>
              <button @click="forwardRequest" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded">
                Forward
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      activeTab: 'proxy',
      isProxyRunning: false,
      isCertInstalled: false,
      isInterceptionEnabled: false,
      proxyPort: 8080,
      filterDomain: '',
      filterMethod: 'ALL',
      interceptedRequests: [],
      showRequestEditor: false,
      selectedRequest: null,
      spiderStartUrl: '',
      spiderMaxDepth: 2,
      spiderRateLimit: 1000,
      spiderResults: [],
      scannerTargetUrl: '', // Add this line
      scannerScanType: 'passive', // Add this line
      scannerResults: [] // Add this line
    }
  },
  computed: {
    filteredRequests() {
      return this.interceptedRequests.filter(req => {
        if (this.filterDomain && !req.url.includes(this.filterDomain)) return false;
        if (this.filterMethod !== 'ALL' && req.method !== this.filterMethod) return false;
        return true;
      });
    }
  },
  methods: {
    toggleProxy() {
      this.isProxyRunning = !this.isProxyRunning;
      if (this.isProxyRunning) {
        this.startProxy();
      } else {
        this.stopProxy();
      }
    },
    toggleInterception() {
      this.isInterceptionEnabled = !this.isInterceptionEnabled;
    },
    generateCert() {
      this.isCertInstalled = true;
    },
    async startProxy() {
      try {
        await axios.post('http://localhost:8080/start');
        this.isProxyRunning = true;
        this.captureTraffic();
      } catch (error) {
        console.error('Failed to start proxy:', error);
      }
    },
    async stopProxy() {
      try {
        await axios.post('http://localhost:8080/stop');
        this.isProxyRunning = false;
      } catch (error) {
        console.error('Failed to stop proxy:', error);
      }
    },
    async captureTraffic() {
      if (!this.isProxyRunning) return;

      // Simulate capturing network traffic
      // In a real scenario, this would involve intercepting HTTP/HTTPS requests
      // and responses using a proxy server

      // Simulate a captured request
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];
      const paths = ['/api/users', '/login', '/dashboard', '/api/products'];
      const request = {
        method: methods[Math.floor(Math.random() * methods.length)],
        url: 'https://example.com' + paths[Math.floor(Math.random() * paths.length)],
        headers: 'Content-Type: application/json',
        body: '{"key": "value"}',
        timestamp: new Date().toLocaleTimeString(),
        status: 200,
        contentType: 'application/json',
        size: 1024
      };

      this.addRequest(request);

      // Continue simulating traffic capture
      setTimeout(() => {
        this.captureTraffic();
      }, 3000);
    },
    editRequest(req) {
      this.selectedRequest = { ...req };
      this.showRequestEditor = true;
    },
    dropRequest() {
      const index = this.interceptedRequests.findIndex(r => r.timestamp === this.selectedRequest.timestamp);
      if (index !== -1) {
        this.interceptedRequests.splice(index, 1);
      }
      this.showRequestEditor = false;
    },
    forwardRequest() {
      // Simulate forwarding the request to the server
      console.log('Forwarding request:', this.selectedRequest);
      // Here you would typically send the request using axios or another library
      // and handle the response
      axios({
          method: this.selectedRequest.method,
          url: this.selectedRequest.url,
          headers: this.selectedRequest.headers,
          data: this.selectedRequest.body,
        })
        .then(response => {
          // Handle the response
          console.log('Response:', response);
          // Update the request with the response status
          const index = this.interceptedRequests.findIndex(r => r.timestamp === this.selectedRequest.timestamp);
          if (index !== -1) {
            this.interceptedRequests[index].status = response.status;
            this.interceptedRequests[index].responseHeaders = JSON.stringify(response.headers);
            this.interceptedRequests[index].responseBody = JSON.stringify(response.data);
          }
        })
        .catch(error => {
          // Handle the error
          console.error('Error:', error);
          // Update the request with the error status
          const index = this.interceptedRequests.findIndex(r => r.timestamp === this.selectedRequest.timestamp);
          if (index !== -1) {
            this.interceptedRequests[index].status = error.response ? error.response.status : 500;
          }
        });

      this.showRequestEditor = false;
    },
    addRequest(request) {
      this.interceptedRequests.unshift(request);
      if (this.interceptedRequests.length > 100) {
        this.interceptedRequests.pop();
      }
    },
    clearRequests() {
      this.interceptedRequests = [];
    },
    async startSpider() {
      try {
        const response = await axios.post('http://localhost:8080/spider', { 
          url: this.spiderStartUrl, 
          maxDepth: this.spiderMaxDepth,
          rateLimit: this.spiderRateLimit 
        });
        this.spiderResults = response.data.results;
      } catch (error) {
        console.error('Failed to start spider:', error);
      }
    },
    async startScanner() {
      try {
        const response = await axios.post('http://localhost:8080/scanner', { 
          url: this.scannerTargetUrl, 
          scanType: this.scannerScanType 
        });
        this.scannerResults = response.data.results;
      } catch (error) {
        console.error('Failed to start scanner:', error);
      }
    }
  },
  mounted() {
    const ws = new WebSocket('ws://localhost:8080');
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'request') {
        this.addRequest({
          method: data.method,
          url: data.url,
          timestamp: new Date().toLocaleTimeString(),
          status: null,
          contentType: null,
          size: null
        });
      } else if (data.type === 'response') {
        const index = this.interceptedRequests.findIndex(req => req.url === data.url && req.status === null);
        if (index !== -1) {
          this.$set(this.interceptedRequests, index, {
            ...this.interceptedRequests[index],
            status: data.statusCode
          });
        }
      }
    };
  }
}
</script>