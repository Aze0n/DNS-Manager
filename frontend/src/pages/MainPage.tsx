// dashboard-layout
import React, { useState, useEffect } from "react";
import { logout, refreshRecords, getDomains } from "../api/client";
import DebugMainForm from "./DebugMainForm";
import ARecords from "./ARecords";
import AAAARecords from "./AAAARecords";
import CNAMERecords from "./CNAMERecords";

type TabKey = "a" | "aaaa" | "cname" | "debug";

const MainPage: React.FC = () => {
  const [tab, setTab] = useState<TabKey>("a");
  const [domains, setDomains] = useState<string[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string | undefined>(undefined);

  useEffect(() => {
    async function load() {
      try {
        const d = await getDomains();
        if (d?.domains && Array.isArray(d.domains)) {
          setDomains(d.domains);
          if (d.domains.length > 0) setSelectedDomain(d.domains[0]);
        }
      } catch (err) {
      }
    }
    load();
  }, []);

  return (
    <div className="container app-root" style={{ paddingTop: 32 }}>
      <div className="main-row">
        <div>
          <div className="card shadow-sm sidebar-card">
            <div className="card-body d-flex flex-column p-3">
              <h5 className="mb-3">menü</h5>
              <div className="mb-3">
                <label className="form-label">Domain</label>
                <select className="form-select mb-3" value={selectedDomain} onChange={(e) => setSelectedDomain(e.target.value)}>
                  <option value="">— alle —</option>
                  {domains.map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              </div>
              <div className="nav flex-column">
                <button className={`btn btn-sm mb-1 ${tab === "a" ? "btn-primary" : "btn-outline-secondary"}`} onClick={() => setTab("a")}>A-Einträge</button>
                <button className={`btn btn-sm mb-1 ${tab === "aaaa" ? "btn-primary" : "btn-outline-secondary"}`} onClick={() => setTab("aaaa")}>AAAA-Einträge</button>
                <button className={`btn btn-sm mb-1 ${tab === "cname" ? "btn-primary" : "btn-outline-secondary"}`} onClick={() => setTab("cname")}>CNAME-Einträge</button>
                <hr />
                <button
                  className={`btn btn-sm btn-outline-primary mb-2`}
                  onClick={async () => {
                    try {
                      const res = await refreshRecords();
                      alert(`Einträge aktualisiert: ${res.stored ?? 0} (type=${res.type})`);
                    } catch (err: any) {
                      alert(err?.message || "Fehler beim Aktualisieren der Einträge");
                    }
                  }}
                >
                  einträge holen
                </button>
                <button
                  className="btn btn-sm btn-outline-secondary mt-auto logout-btn"
                  onClick={async () => {
                    try {
                      await logout();
                    } catch (err) {}
                    window.location.href = "/login";
                  }}
                >
                  abmelden
                </button>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div className="card shadow-sm content-card">
            {tab === "a" && <ARecords selectedDomain={selectedDomain} />}
            {tab === "aaaa" && <AAAARecords selectedDomain={selectedDomain} />}
            {tab === "cname" && <CNAMERecords selectedDomain={selectedDomain} />}
            {tab === "debug" && <DebugMainForm selectedDomain={selectedDomain} />}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MainPage;
