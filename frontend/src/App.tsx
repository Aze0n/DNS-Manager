// datei src/App.tsx
import React, { useEffect, useState } from "react";
import { checkSetup } from "./api/client";
import LoginPage from "./pages/LoginPage";
import SetupPage from "./pages/SetupPage";
import MainPage from "./pages/MainPage";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";

const App: React.FC = () => {
  const [setupNeeded, setSetupNeeded] = useState<boolean | null>(null);
  const [loggedIn, setLoggedIn] = useState<boolean | null>(null);

  useEffect(() => {
    const fetchInitial = async () => {
      try {
        const setupResp = await checkSetup();
        setSetupNeeded(setupResp.needs_setup);
  } catch (err) {
  console.error("checkSetup failed", err);
  setSetupNeeded(false); // sicherer Fallback
      }

      try {
        const meResp = await fetch("/api/me", { credentials: "include" });
        setLoggedIn(meResp.ok);
      } catch (err) {
        console.error("/api/me failed", err);
        setLoggedIn(false);
      }
    };

    fetchInitial();
  }, []);

  if (setupNeeded === null || loggedIn === null) {
    return <div className="container mt-5">Lädt…</div>;
  }

  return (
    <Router>
      <Routes>
        {setupNeeded ? (
          <Route path="*" element={<SetupPage onSetupComplete={() => setSetupNeeded(false)} />} />
        ) : (
          <>
            <Route path="/" element={<LoginPage onLoginSuccess={() => setLoggedIn(true)} />} />
            <Route
              path="/main"
              element={loggedIn ? <MainPage /> : <Navigate to="/" replace />}
            />
            <Route path="*" element={<Navigate to={loggedIn ? "/main" : "/"} replace />} />
          </>
        )}
      </Routes>
    </Router>
  );
};

export default App;
