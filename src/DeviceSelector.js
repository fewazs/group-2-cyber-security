import React, { useState, useEffect } from 'react';
import axios from 'axios';

function DeviceSelector({ onSelect }) {
  const [devices, setDevices] = useState([]);
  const [selected, setSelected] = useState('all');

  useEffect(() => {
    async function fetchDevices() {
      const res = await axios.get('/admin/devices');
      setDevices(res.data.devices);
    }
    fetchDevices();
  }, []);

  return (
    <div>
      <label>Show DNS queries for: </label>
      <select value={selected} onChange={e => { setSelected(e.target.value); onSelect(e.target.value); }}>
        <option value="all">All Devices</option>
        {devices.map((dev, idx) => (
          <option key={idx} value={dev}>{dev}</option>
        ))}
      </select>
    </div>
  );
}

export default DeviceSelector;
