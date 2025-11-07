// a-records seite (platzhalter)
import React, { useState, useEffect } from "react";
import { getRecordsForDomain } from "../api/client";

interface ARecordsProps { selectedDomain?: string }
const ARecords: React.FC<ARecordsProps> = ({ selectedDomain }) => {
  const [showModal, setShowModal] = useState(false);
  const [records, setRecords] = useState<any[]>([]);
  const [pendingKeys, setPendingKeys] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalName, setModalName] = useState("");
  const [modalContent, setModalContent] = useState("");
  const [modalTTL, setModalTTL] = useState<string | undefined>(undefined);
  const [modalDyndns, setModalDyndns] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await getRecordsForDomain("A", selectedDomain);
        setRecords(res.records || []);
      } catch (err) {
        setRecords([]);
      }
    }
    load();
  }, [selectedDomain]);

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3">
  <h2>A-Records</h2>
        <div>
          <button className="btn btn-secondary" onClick={() => { setModalName(""); setModalContent(""); setModalTTL(undefined); setModalDyndns(false); setShowModal(true); }}>
            Neuer Eintrag
          </button>
        </div>
      </div>

      <div className="table-responsive">
        <table className="table table-striped table-sm">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Name</th>
              <th>Typ</th>
              <th>Ziel</th>
              <th>TTL</th>
              <th>DynDNS</th>
              <th>Aktionen</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td colSpan={7} className="text-muted">Keine Daten vorhanden.</td>
              </tr>
            )}
            {records.map((r, idx) => (
              <tr key={idx}>
                <td>{r.domain}</td>
                <td>{r.name}</td>
                <td>{r.type}</td>
                <td>{r.content}</td>
                <td>{r.ttl ?? '-'}</td>
                <td>
                  {(() => {
                    const key = `${r.domain}|${r.name}|${r.type}`;
                    const isPending = pendingKeys.includes(key);
                    return (
                      <input type="checkbox" checked={!!r.dyndns} disabled={isPending} onChange={async (e) => {
                        const newVal = e.target.checked;
                        setLoading(true);
                        setPendingKeys(prev => [...prev, key]);
                        try {
                          const res = await fetch(`/api/records`, { method: 'PATCH', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: r.domain, name: r.name, type: r.type, dyndns: newVal }) });
                          if (!res.ok) {
                            let msg = 'Update der DynDNS-Einstellung fehlgeschlagen.';
                            try {
                              const err = await res.json().catch(() => null);
                              const d = err?.detail ?? err?.message; if (typeof d === 'string') msg = d;
                            } catch {}
                            throw new Error(msg);
                          }
                          const list = await getRecordsForDomain('A', selectedDomain);
                          setRecords(list.records || []);
                        } catch (err) {
                          alert((err as any)?.message || 'Fehler beim Aktualisieren.');
                        } finally {
                          setPendingKeys(prev => prev.filter(k => k !== key));
                          setLoading(false);
                        }
                      }} />
                    );
                  })()}
                </td>
                <td>
                  <button className="btn btn-sm btn-outline-secondary" onClick={async () => {
                    if (!confirm(`Eintrag wirklich löschen? ${r.name} ${r.type} → ${r.content}`)) return;
                    setLoading(true);
                    try {
                      await fetch(`/api/records`, { method: 'DELETE', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) });
                      setRecords(prev => prev.filter(x => !(x.domain === r.domain && x.name === r.name && x.type === r.type && x.content === r.content)));
                    } catch (e: any) {
                      alert(e?.message || 'Fehler beim Löschen.');
                    } finally {
                      setLoading(false);
                    }
                  }}>Löschen</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* modal: neuer eintrag (Domain comes from selectedDomain, type fixed to A) */}
      {showModal && (
        <>
          <div className="modal-backdrop fade show" />
          <div className="modal d-block" tabIndex={-1}>
            <div className="modal-dialog">
              <div className="modal-content p-3">
                <div className="modal-header">
                  <h5 className="modal-title">Neuer A-Record</h5>
                  <button className="btn-close" onClick={() => setShowModal(false)} />
                </div>
                <div className="modal-body">
                                  <form onSubmit={async (e) => {
                                    e.preventDefault();
                                    if (!selectedDomain) { alert('Bitte wähle eine Domain aus.'); return; }
                                    const name = modalName.trim();
                                    let content = modalContent.trim();
                                    const ttlStr = modalTTL ?? '';
                                    const ttl = ttlStr ? parseInt(ttlStr as string, 10) : undefined;
                                    const dyndns = modalDyndns;
                                    if (!name) { alert('Bitte gib einen Namen (Subdomain) ein.'); return; }
                                    if (!content && !dyndns) { alert('Bitte gib ein Ziel (IP-Adresse) ein.'); return; }
                                    if (!ttlStr) { alert('Bitte gib eine TTL an.'); return; }
                                    if (isNaN(Number(ttl)) || (ttl !== undefined && ttl <= 0)) { alert('TTL muss eine positive ganze Zahl sein.'); return; }
                                    setLoading(true);
                                    try {
                                      const payload: any = { type: 'A', name, content };
                                      if (typeof ttl !== 'undefined') payload.ttl = ttl;
                                      if (dyndns) payload.dyndns = true;
                                      if (dyndns && content.toLowerCase() === 'auto') {
                                        try {
                                          const r = await fetch('https://api.ipify.org?format=json');
                                          if (r.ok) {
                                            const j = await r.json();
                                            payload.provider_content = j.ip;
                                          }
                                        } catch (e) {
                                        }
                                        payload.content = 'auto';
                                      }

                                      const res = await fetch(`/api/domains/${selectedDomain}/records`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                                      if (!res.ok) {
                                        let msg = 'Erstellen fehlgeschlagen.';
                                        try { const err = await res.json().catch(() => null); const d = err?.detail ?? err?.message; if (typeof d === 'string') msg = d; } catch {}
                                        throw new Error(msg);
                                      }
                                      const body = await res.json();
                                      setRecords(prev => [{ domain: selectedDomain, name, type: 'A', content, ttl, dyndns }, ...prev]);
                                      setShowModal(false);
                                      alert(body.message || 'Record erstellt.');
                                    } catch (err: any) {
                                      alert(err?.message || 'Fehler beim Erstellen.');
                                    } finally {
                                      setLoading(false);
                                    }
                                  }}>
                                      <div className="mb-3">
                                        <label className="form-label">Name (Subdomain)</label>
                                        <input name="name" value={modalName} onChange={e => setModalName(e.target.value)} type="text" className="form-control" placeholder="www" />
                                      </div>
                                      <div className="mb-3">
                                        <label className="form-label">Ziel / IP-Adresse</label>
                                        <input name="content" value={modalContent} onChange={e => setModalContent(e.target.value)} type="text" className="form-control" placeholder="1.2.3.4" required disabled={modalDyndns} />
                                      </div>
                                      <div className="mb-3">
                                        <label className="form-label">TTL (Sekunden)</label>
                                        <input name="ttl" value={modalTTL ?? ''} onChange={e => setModalTTL(e.target.value)} type="number" className="form-control" placeholder="3600" disabled={modalDyndns} />
                                      </div>
                                      <div className="form-check mb-3">
                                        <input name="dyndns" className="form-check-input" type="checkbox" id="dyndnsCheck" checked={modalDyndns} onChange={e => { const v = e.target.checked; setModalDyndns(v); if (v) { setModalContent('auto'); setModalTTL('60'); } else { setModalContent(''); setModalTTL(undefined); } }} />
                                        <label className="form-check-label" htmlFor="dyndnsCheck">DynDNS aktiv (auto)</label>
                                      </div>
                    <div className="d-flex justify-content-end">
                      <button type="button" className="btn btn-secondary me-2" onClick={() => setShowModal(false)}>Abbrechen</button>
                      <button type="submit" className="btn btn-primary">Erstellen</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
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
};

export default ARecords;
