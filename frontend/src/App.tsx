import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, Activity, List, Zap, AlertTriangle, Play, Trash2, Plus } from 'lucide-react';

const API_BASE = "http://localhost:8000";

interface Rule {
  id: number;
  action: string;
  src_ip: string;
  dst_port: number;
  protocol: string;
}

interface LogEntry {
  timestamp: string;
  src_ip: string;
  dst_port: string;
  protocol: string;
  action: string;
}

interface Threat {
  type: string;
  src_ip: string;
  count: number;
  details: string;
}

function App() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [newPacket, setNewPacket] = useState({ src_ip: "192.168.1.1", dst_port: 80, protocol: "TCP" });
  const [newRule, setNewRule] = useState({ action: "DENY", src_ip: "", dst_port: 80, protocol: "TCP" });

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [rulesRes, logsRes, threatsRes] = await Promise.all([
        axios.get(`${API_BASE}/rules`),
        axios.get(`${API_BASE}/logs`),
        axios.get(`${API_BASE}/threats`)
      ]);
      setRules(rulesRes.data);
      setLogs(logsRes.data);
      setThreats(threatsRes.data);
    } catch (err) {
      console.error("Error fetching data:", err);
    }
  };

  const addRule = async () => {
    if (!newRule.src_ip) return;
    await axios.post(`${API_BASE}/rules`, newRule);
    setNewRule({ ...newRule, src_ip: "" });
    fetchData();
  };

  const deleteRule = async (id: number) => {
    await axios.delete(`${API_BASE}/rules/${id}`);
    fetchData();
  };

  const simulatePacket = async () => {
    await axios.post(`${API_BASE}/simulate`, newPacket);
    fetchData();
  };

  const downloadReport = async () => {
    const res = await axios.get(`${API_BASE}/report`);
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res.data, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "security_report.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <div className="app-container">
      <header>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield color="var(--accent-cyan)" size={32} />
          <h1>SENTINEL FIREWALL ENGINE</h1>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button onClick={downloadReport} className="secondary" style={{ marginRight: '15px', fontSize: '0.8rem' }}>Export Report</button>
          <div className="live-indicator"></div>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent-green)', fontWeight: 'bold' }}>SYSTEM ACTIVE</span>
        </div>
      </header>

      <div className="dashboard-grid">
        {/* Rules Manager */}
        <section className="panel" style={{ gridRow: 'span 2' }}>
          <h2><List size={20} /> Firewall Rules</h2>
          <div className="scrollable">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Source IP</th>
                  <th>Port</th>
                  <th>Proto</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => (
                  <tr key={rule.id}>
                    <td><span className={`status status-${rule.action.toLowerCase()}`}>{rule.action}</span></td>
                    <td>{rule.src_ip}</td>
                    <td>{rule.dst_port}</td>
                    <td>{rule.protocol}</td>
                    <td>
                      <Trash2
                        size={16}
                        style={{ cursor: 'pointer', color: 'var(--text-secondary)' }}
                        onClick={() => deleteRule(rule.id)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
            <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem' }}>Add New Rule</h3>
            <div className="input-group">
              <input
                placeholder="Source IP (or 'any' or CIDR)"
                value={newRule.src_ip}
                onChange={e => setNewRule({ ...newRule, src_ip: e.target.value })}
              />
              <div style={{ display: 'flex', gap: '10px' }}>
                <input
                  type="number"
                  placeholder="Port"
                  value={newRule.dst_port}
                  onChange={e => setNewRule({ ...newRule, dst_port: parseInt(e.target.value) })}
                  style={{ flex: 1 }}
                />
                <select
                  value={newRule.action}
                  onChange={e => setNewRule({ ...newRule, action: e.target.value })}
                  style={{ flex: 1 }}
                >
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                </select>
              </div>
              <button onClick={addRule}><Plus size={16} /> Add Rule</button>
            </div>
          </div>
        </section>

        {/* Traffic Simulator */}
        <section className="panel">
          <h2><Zap size={20} /> Traffic Simulator</h2>
          <div style={{ display: 'flex', gap: '15px', alignItems: 'flex-end' }}>
            <div className="input-group" style={{ flex: 2, marginBottom: 0 }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Source IP</label>
              <input
                value={newPacket.src_ip}
                onChange={e => setNewPacket({ ...newPacket, src_ip: e.target.value })}
              />
            </div>
            <div className="input-group" style={{ flex: 1, marginBottom: 0 }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Port</label>
              <input
                type="number"
                value={newPacket.dst_port}
                onChange={e => setNewPacket({ ...newPacket, dst_port: parseInt(e.target.value) })}
              />
            </div>
            <button onClick={simulatePacket} style={{ height: '42px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Play size={16} /> Inject Packet
            </button>
          </div>
        </section>

        {/* Log Viewer & Alerts */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
          <section className="panel">
            <h2><Activity size={20} /> Access Logs</h2>
            <div className="scrollable">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Port</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.slice().reverse().map((log, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{log.timestamp.split(' ')[1]}</td>
                      <td>{log.src_ip}</td>
                      <td>{log.dst_port}</td>
                      <td><span className={`status status-${log.action.toLowerCase()}`}>{log.action}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <h2><AlertTriangle size={20} /> Security Threats</h2>
            <div className="scrollable">
              {threats.length === 0 ? (
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', textAlign: 'center', marginTop: '2rem' }}>
                  No threats detected.
                </div>
              ) : (
                threats.map((threat, i) => (
                  <div key={i} className="threat-card">
                    <h3>{threat.type}</h3>
                    <p>{threat.details}</p>
                    <div style={{ marginTop: '5px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                      IP: {threat.src_ip} | Blocks: {threat.count}
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

export default App;
