import React, { useEffect, useState } from "react";

const AdminDashboard = () => {
  const [dnsData, setDnsData] = useState([]);

  // Fetch DNS traffic data from JSON file
  useEffect(() => {
    fetch("/capture/all_traffic.json")
      .then((response) => response.json())
      .then((data) => setDnsData(data))
      .catch((error) => console.error("Error loading DNS data:", error));
  }, []);

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>Admin Dashboard - DNS Traffic</h1>
      {dnsData.length === 0 ? (
        <p>Loading DNS traffic data...</p>
      ) : (
        <table border="1" cellPadding="10">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Query</th>
              <th>Response</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            {dnsData.map((entry, index) => (
              <tr key={index}>
                <td>{entry.timestamp}</td>
                <td>{entry.query}</td>
                <td>{entry.response || "N/A"}</td>
                <td>{entry.type}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default AdminDashboard;
