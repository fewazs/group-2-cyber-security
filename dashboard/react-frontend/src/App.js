import React, { useState } from "react";
import Login from "./Login";
import StatsDashboard from "./StatsDashboard";
import AdminDashboard from "./AdminDashboard";

function App() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [isAdmin, setIsAdmin] = useState(true); // For demo, assume admin after login

  return (
    <div>
      {!loggedIn ? (
        <Login onLogin={() => setLoggedIn(true)} />
      ) : (
        <>
          <StatsDashboard />
          {isAdmin && <AdminDashboard />}
        </>
      )}
    </div>
  );
}

export default App;

