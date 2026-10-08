/**
 * IPC Client for SOC/DFIR Platform
 * Implements JSON-RPC 2.0 with RFC 7807 Problem Details handling
 */
export class IpcClient {
  constructor(endpointUrl = null) {
    if (!endpointUrl) {
      if (typeof window !== 'undefined' && window.location && window.location.origin && window.location.origin.startsWith('http')) {
        this.endpointUrl = `${window.location.origin}/rpc`;
      } else {
        this.endpointUrl = 'http://127.0.0.1:8080/rpc';
      }
    } else {
      this.endpointUrl = endpointUrl;
    }
    this.apiVersion = 1;
  }

  async call(method, params = {}) {
    const requestId = 'req_' + Math.random().toString(36).substring(2, 9);
    const token = (params && params.token) || (typeof localStorage !== 'undefined' ? localStorage.getItem('soc_session_token') : null);
    const finalParams = token ? { ...params, token } : { ...params };
    const payload = {
      api_version: this.apiVersion,
      request_id: requestId,
      method: method,
      params: finalParams
    };

    let response;
    try {
      response = await fetch(this.endpointUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (err) {
      const netErr = new Error(`Движок недоступен по адресу ${this.endpointUrl}: ${err.message}`);
      netErr.transport = true;
      throw netErr;
    }

    if (response.status === 401 && method !== 'auth.login' && method !== 'auth.session'
        && typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('soc:unauthorized'));
    }

    let data;
    try {
      data = await response.json();
    } catch (_) {
      throw new Error(`Движок вернул HTTP ${response.status}`);
    }
    if (data.error) {
      // Auth refusals (wrong password, expired session) are expected user
      // errors, shown in the UI; everything else is logged as an error.
      (data.error.status === 401 ? console.warn : console.error)('IPC Error:', data.error);
      const err = new Error(data.error.detail || data.error.title || 'RPC Failed');
      err.status = data.error.status;
      err.code = data.error.code;
      err.problem = data.error;
      throw err;
    }
    return data.result;
  }

  async getHostOverview(hostId) {
    return this.call('host.overview', hostId ? { host_id: hostId } : {});
  }

  async getHostSnapshot(hostId) {
    return this.call('host.snapshot', hostId ? { host_id: hostId } : {});
  }

  async getHostProcesses(hostId) {
    return this.call('host.processes', hostId ? { host_id: hostId } : {});
  }

  async getHostSockets(hostId) {
    return this.call('host.sockets', hostId ? { host_id: hostId } : {});
  }

  async getHostServices(hostId) {
    return this.call('host.services', hostId ? { host_id: hostId } : {});
  }

  async getHostPersistence(hostId) {
    return this.call('host.persistence', hostId ? { host_id: hostId } : {});
  }

  async getHostSoftware(hostId) {
    return this.call('host.software', hostId ? { host_id: hostId } : {});
  }
}
