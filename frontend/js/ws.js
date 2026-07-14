class ScanWebSocket {
  constructor() {
    this.ws = null;
    this.reconnectAttempts = 0;
    this.maxReconnect = 20;
    this.listeners = {};
    this.statusEl = document.getElementById('ws-status');
  }

  connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/api/v1/ws/scans`;

    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.setStatus('connected');
    };

    this.ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        const cbs = this.listeners[msg.type] || [];
        cbs.forEach(fn => fn(msg));
      } catch (e) {
        console.warn('WS message parse error:', e);
      }
    };

    this.ws.onclose = () => {
      this.setStatus('reconnecting');
      if (this.reconnectAttempts < this.maxReconnect) {
        const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 10000);
        setTimeout(() => this.connect(), delay);
        this.reconnectAttempts++;
      } else {
        this.setStatus('offline');
      }
    };

    this.ws.onerror = () => this.ws.close();
  }

  on(type, callback) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(callback);
  }

  setStatus(state) {
    if (!this.statusEl) return;
    if (state === 'connected') {
      this.statusEl.textContent = '\u25CF Live';
      this.statusEl.style.color = '#22c55e';
    } else if (state === 'reconnecting') {
      this.statusEl.textContent = '\u25CF Reconnecting...';
      this.statusEl.style.color = '#eab308';
    } else {
      this.statusEl.textContent = '\u25CF Offline';
      this.statusEl.style.color = '#ef4444';
    }
  }
}

const wsClient = new ScanWebSocket();
wsClient.connect();
