import React, { useState, useEffect } from 'react';
import axios from 'axios';
import DeviceSelector from './DeviceSelector';

function StatsDashboard() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [device, setDevice] = useState('all');
  const [showSpotify, setShowSpotify] = useState(false);
  const [queries, setQueries] = useState([]);
  const [trafficMode, setTrafficMode] = useState('dns'); // 'dns' or 'all'
  const [allTraffic, setAllTraffic] = useState([]);
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureFilename, setCaptureFilename] = useState("");

  useEffect(() => {
    async function fetchStats() {
      const res = await axios.get('/stats');
      setStats(res.data);
      const alertsRes = await axios.get('/alerts');
      setAlerts(alertsRes.data);
      if (trafficMode === 'dns') {
        const queriesRes = await axios.get('/api/dns-stats');
        setQueries(queriesRes.data.queries || []);
      } else {
        const allRes = await axios.get('/api/all-traffic');
        setAllTraffic(allRes.data || []);
      }
    }
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [device, showSpotify, trafficMode]);

  const handleCapture = async () => {
    const filename = window.prompt("Enter filename for new capture:", `capture_${Date.now()}.json`);
    if (!filename) return;
    setCaptureFilename(filename);
    await axios.post('/api/capture/start', { filename });
    setIsCapturing(true);
  };
  const handleStop = async () => {
    await axios.post('/api/capture/stop');
    setIsCapturing(false);
  };
  const handleSave = async () => {
    const filename = window.prompt("Enter filename to save as:", captureFilename || `capture_${Date.now()}.json`);
    if (!filename) return;
    await axios.post('/api/capture/save', { filename });
    alert(`Capture saved as ${filename}!`);
  };

  const filteredQueries = queries.filter(q => {
    if (device !== 'all' && q.src_ip !== device) return false;
    if (showSpotify && !q.query.includes('spotify')) return false;
    return true;
  });

  const filteredAllTraffic = allTraffic.filter(pkt => {
    if (device !== 'all' && pkt.src_ip !== device) return false;
    return true;
  });

  if (!stats) return <div>Loading statistics...</div>;

  return (
    <div className="dashboard-container">
      <h2>Spotify DNS Traffic Statistics</h2>
      <div style={{ marginBottom: '1em' }}>
        <button onClick={handleCapture} disabled={isCapturing}>Capture</button>
        <button onClick={handleStop} disabled={!isCapturing}>Stop</button>
        <button onClick={handleSave}>Save</button>
      </div>
      <DeviceSelector onSelect={setDevice} />
      <label>
        <input type="checkbox" checked={showSpotify} onChange={e => setShowSpotify(e.target.checked)} />
        Show only Spotify queries
      </label>
      <label>
        <span>Traffic Mode: </span>
        <select value={trafficMode} onChange={e => setTrafficMode(e.target.value)}>
          <option value="dns">DNS Only</option>
          <option value="all">All Traffic</option>
        </select>
      </label>
      <ul>
        <li>Real Spotify DNS Requests: {stats.real_spotify}</li>
        <li>Fake Spotify DNS Tunneling Attempts: {stats.fake_spotify}</li>
        <li>Alerts: {stats.alerts}</li>
      </ul>
      <h3>Recent Alerts</h3>
      <ul>
        {alerts.map((alert, idx) => (
          <li key={idx}>{alert}</li>
        ))}
      </ul>
      {trafficMode === 'dns' ? (
        <>
          <h3>DNS Queries</h3>
          <ul>
            {filteredQueries.map((q, idx) => (
              <li key={idx}>{q.src_ip}: {q.query}</li>
            ))}
          </ul>
        </>
      ) : (
        <>
          <h3>All Network Traffic</h3>
          <ul>
            {filteredAllTraffic.map((pkt, idx) => (
              <li key={idx}>{pkt.timestamp}: {pkt.src_ip} → {pkt.dst_ip} [{pkt.proto}] Size: {pkt.pkt_size}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

export default StatsDashboard;
