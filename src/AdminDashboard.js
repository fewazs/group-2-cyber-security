import React, { useState, useEffect } from 'react';
import axios from 'axios';

function AdminDashboard() {
  const [domain, setDomain] = useState('');
  const [duration, setDuration] = useState('');
  const [devices, setDevices] = useState([]);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    const res = await axios.get('/admin/devices');
    setDevices(res.data.devices);
  };

  const blockDomain = async () => {
    const res = await axios.post('/admin/block', { domain });
    setMessage(res.data.success ? `Blocked ${domain}` : 'Block failed');
  };

  const unblockDomain = async () => {
    const res = await axios.post('/admin/unblock', { domain });
    setMessage(res.data.success ? `Unblocked ${domain}` : 'Unblock failed');
  };

  const suspendDomain = async () => {
    const res = await axios.post('/admin/suspend', { domain, duration });
    setMessage(res.data.success ? `Suspended ${domain} for ${duration} seconds` : 'Suspend failed');
  };

  return (
    <div className="admin-dashboard">
      <h2>Admin Controls</h2>
      <input
        type="text"
        placeholder="Domain"
        value={domain}
        onChange={e => setDomain(e.target.value)}
      />
      <input
        type="number"
        placeholder="Suspend Duration (seconds)"
        value={duration}
        onChange={e => setDuration(e.target.value)}
      />
      <button onClick={blockDomain}>Block</button>
      <button onClick={unblockDomain}>Unblock</button>
      <button onClick={suspendDomain}>Suspend</button>
      {message && <p>{message}</p>}
      <h3>Connected Devices</h3>
      <ul>
        {devices.map((dev, idx) => (
          <li key={idx}>{dev}</li>
        ))}
      </ul>
    </div>
  );
}

export default AdminDashboard;
