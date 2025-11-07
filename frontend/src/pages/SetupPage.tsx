// datei src/pages/SetupPage.tsx
import React, { useState } from "react";
import { setup, login } from "../api/client";
import { useNavigate } from "react-router-dom";

type Props = {
  onSetupComplete?: () => void;
};

type Checks = {
  min: boolean;
  upper: boolean;
  lower: boolean;
  digit: boolean;
  special: boolean;
  nospace: boolean;
};

const PasswordHints: React.FC<{ checks: Checks }> = ({ checks }) => {
  const row = (v: boolean, txt: string) => (
    <div style={{display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6}}>
      <span style={{width:12, height:12, borderRadius:6, display:'inline-block', background: v ? '#28a745' : '#6c757d'}} />
      <span style={{color: '#fff', fontSize: 14}}>{txt}</span>
    </div>
  );
  return (
    <div style={{backgroundColor: '#0b0b0d', padding: 12, borderRadius: 8, boxShadow: '0 6px 18px rgba(0,0,0,0.6)'}}>
      {row(checks.min, 'mind. 12 Zeichen')}
      {row(checks.upper, 'Großbuchstabe')}
      {row(checks.lower, 'Kleinbuchstabe')}
      {row(checks.digit, 'Ziffer')}
      {row(checks.special, 'Sonderzeichen')}
      {row(checks.nospace, 'keine Leerzeichen')}
    </div>
  );
};

const SetupPage: React.FC<Props> = ({ onSetupComplete }) => {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiSecret, setApiSecret] = useState("");
  const [provider, setProvider] = useState("porkbun");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateForm = (): string | null => {
    const minLen = 12;
    if (password.length < minLen) return `Passwort muss mindestens ${minLen} Zeichen haben.`;
    if (!/[A-Z]/.test(password)) return "Mindestens ein Großbuchstabe erforderlich.";
    if (!/[a-z]/.test(password)) return "Mindestens ein Kleinbuchstabe erforderlich.";
    if (!/\d/.test(password)) return "Mindestens eine Ziffer erforderlich.";
    if (!/[!@#$%^&*()_\-+=\[\]{};:'\\\"\\|,.<>\/?`~]/.test(password)) return "Mindestens ein Sonderzeichen erforderlich.";
    if (/\s/.test(password)) return "Passwort darf keine Leerzeichen enthalten.";
    if (!apiKey) return "API Key darf nicht leer sein.";
    if (!apiSecret) return "API Secret darf nicht leer sein.";
    return null;
  };

  const passwordChecks = () => {
    return {
      min: password.length >= 12,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      digit: /\d/.test(password),
      special: /[!@#$%^&*()_\-+=\[\]{};:'\\\"\\|,.<>\/?`~]/.test(password),
      nospace: !/\s/.test(password),
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const vErr = validateForm();
    if (vErr) {
      setError(vErr);
      return;
    }

    setLoading(true);
    try {
      await setup(password, apiKey, apiSecret, provider);
      await login(password);
    if (onSetupComplete) onSetupComplete();
      navigate("/main", { replace: true });
    } catch (err: any) {
      setError(err?.message || "Setup fehlgeschlagen");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <h1>Initiales Setup</h1>
      {error && <div className="alert alert-danger">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="mb-3">
          <label htmlFor="password" className="form-label">Passwort</label>
          <input
            type="password"
            id="password"
            className="form-control"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
          <div className="form-text mt-2">
            <small>
              <PasswordHints checks={passwordChecks()} />
            </small>
          </div>
        </div>

        <div className="mb-3">
          <label htmlFor="apiKey" className="form-label">API Key</label>
          <input
            type="text"
            id="apiKey"
            className="form-control"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            required
          />
        </div>

        <div className="mb-3">
          <label htmlFor="apiSecret" className="form-label">API Secret</label>
          <input
            type="text"
            id="apiSecret"
            className="form-control"
            value={apiSecret}
            onChange={e => setApiSecret(e.target.value)}
            required
          />
        </div>

        <div className="mb-3">
          <label htmlFor="provider" className="form-label">Provider</label>
          <select
            id="provider"
            className="form-select"
            value={provider}
            onChange={e => setProvider(e.target.value)}
          >
            <option value="porkbun">Porkbun</option>
          </select>
        </div>

        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? "Einrichten..." : "Setup durchführen"}
        </button>
      </form>
      {loading && (
        <>
          <div style={{ position: 'fixed', inset: 0, zIndex: 2000, backgroundColor: 'rgba(0,0,0,0.4)' }} />
          <div style={{ position: 'fixed', inset: 0, zIndex: 2001, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="text-white text-center">
              <div className="spinner-border text-light" role="status" style={{ width: '3rem', height: '3rem' }} />
              <div className="mt-2">Einrichtung läuft…</div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default SetupPage;
