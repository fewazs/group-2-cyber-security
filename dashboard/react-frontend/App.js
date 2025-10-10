import React, { useEffect, useState } from "react";
import axios from "axios";

function App() {
  const [stats, setStats] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [blocked, setBlocked] = useState([]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    const statsRes = await axios.get("/api/dns-stats");
    setStats(statsRes.data);
    const alertsRes = await axios.get("/api/alerts");
    setAlerts(alertsRes.data.alerts);
    const blockedRes = await axios.get("/api/blocked");
    setBlocked(blockedRes.data.blocked);
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>DNS Tunneling Prevention Dashboard</h1>
      <h2>DNS Traffic Stats</h2>
      <pre>{JSON.stringify(stats, null, 2)}</pre>
      <h2>Alerts</h2>
      <ul>
        {alerts.map((a, i) => (
          <li key={i}>{a}</li>
        ))}
      </ul>
      <h2>Blocked Domains/IPs</h2>
      <ul>
        {blocked.map((b, i) => (
          <li key={i}>{b}</li>
        ))}
      </ul>
    </div>
  );
}

export default App;
