// debug-form (kopie der alten hauptansicht)
import React, { useEffect, useState } from "react";
import axios from "axios";
import { getDomains } from "../api/client";

interface DebugMainFormProps { selectedDomain?: string }
const DebugMainForm: React.FC<DebugMainFormProps> = ({ selectedDomain }) => {
  const [domain, setDomain] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const [message, setMessage] = useState("");
  const [domains, setDomains] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    async function fetchDomains() {
      setLoading(true);
      setError("");
      try {
        const data = await getDomains();
        if (data?.domains && Array.isArray(data.domains)) {
          setDomains(data.domains);
          if (selectedDomain) {
            setDomain(selectedDomain);
          } else if (data.domains.length > 0) setDomain(data.domains[0]);
        }
      } catch (err: any) {
        if (err?.message === "unauthorized") {
          window.location.href = "/login";
          return;
        }
        setError(err?.message || "fehler beim laden der domains");
      } finally {
        setLoading(false);
      }
    }
    fetchDomains();
  }, []);

  useEffect(() => {
    if (selectedDomain) setDomain(selectedDomain);
  }, [selectedDomain]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitLoading(true);
    setMessage("");
    setError("");
    try {
      const payload = { type: recordType, name, content };
      const response = await axios.post(
        `/api/domains/${domain}/records`,
        payload,
        { withCredentials: true }
      );
      setMessage(response.data.message || "Eintrag erfolgreich erstellt!");
    } catch (error: any) {
      const detail = error.response?.data?.detail || error.message;
      setError(detail || "fehler beim erstellen des eintrags");
    } finally {
      setSubmitLoading(false);
    }
  };

  return (
    <div>
      <div className="d-flex align-items-center mb-3">
        <h2 className="me-auto">debug formular</h2>
      </div>

      {loading && <div className="alert alert-secondary">lade domains…</div>}
      {error && <div className="alert alert-danger">{error}</div>}

      <form onSubmit={handleSubmit} className="p-3 border rounded bg-light">
        <div className="mb-3">
          <label className="form-label">Domain</label>
          {domains.length > 0 ? (
            <select
              className="form-select"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required
            >
              {domains.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              className="form-control"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required
            />
          )}
        </div>

        <div className="mb-3">
          <label className="form-label">Typ</label>
          <select
            className="form-select"
            value={recordType}
            onChange={(e) => setRecordType(e.target.value)}
          >
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="CNAME">CNAME</option>
          </select>
        </div>

        <div className="mb-3">
          <label className="form-label">Name (Subdomain)</label>
          <input
            type="text"
            className="form-control"
            placeholder="www"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <div className="mb-3">
          <label className="form-label">Ziel / IP-Adresse</label>
          <input
            type="text"
            className="form-control"
            placeholder="1.2.3.4 oder cname.example.com"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            required
          />
        </div>

        <button type="submit" className="btn btn-primary" disabled={submitLoading}>
          {submitLoading ? "Bitte warten…" : "DNS-Eintrag erstellen"}
        </button>
      </form>

      {message && <div className="alert alert-info mt-3">{message}</div>}
    </div>
  );
};

export default DebugMainForm;
