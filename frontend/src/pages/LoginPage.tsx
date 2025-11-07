// login seite
import React, { useState } from "react";
import { login } from "../api/client";
import { useNavigate } from "react-router-dom";

type Props = {
  onLoginSuccess?: () => void;
};

export default function LoginPage({ onLoginSuccess }: Props) {
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
  try {
    setLoading(true);
  const res = await login(password);
    setMessage(res.message);
    if (onLoginSuccess) onLoginSuccess();
    navigate("/main", { replace: true });
  } catch (err: any) {
    const msg = typeof err === "string" ? err : err?.message || JSON.stringify(err) || "login fehlgeschlagen";
    setMessage(msg);
  } finally {
    setLoading(false);
  }
  };


  return (
    <div className="container mt-5">
      <h1>Anmeldung</h1>
      {message && <div className="alert alert-info">{message}</div>}
      <form onSubmit={handleLogin}>
        <div className="mb-3">
          <label htmlFor="password" className="form-label">Passwort</label>
          <input
            type="password"
            className="form-control"
            id="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
        </div>
  <button type="submit" className="btn btn-primary me-2" disabled={loading}>{loading ? 'Bitte warten…' : 'Anmelden'}</button>
      </form>
      {loading && (
        <>
          <div style={{ position: 'fixed', inset: 0, zIndex: 2000, backgroundColor: 'rgba(0,0,0,0.4)' }} />
          <div style={{ position: 'fixed', inset: 0, zIndex: 2001, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="text-white text-center">
              <div className="spinner-border text-light" role="status" style={{ width: '3rem', height: '3rem' }} />
              <div className="mt-2">Bitte warten…</div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
