// aaaa-records seite (platzhalter)
import React, { useState, useEffect } from "react";
import { getRecordsForDomain } from "../api/client";
interface AAAARecordsProps { selectedDomain?: string }
const AAAARecords: React.FC<AAAARecordsProps> = ({ selectedDomain }) => {
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
        const res = await getRecordsForDomain("AAAA", selectedDomain);
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
        <h2>AAAA-Einträge</h2>
        <div>
          <button className="btn btn-secondary" onClick={() => { setModalName(""); setModalContent(""); setModalTTL(undefined); setModalDyndns(false); setShowModal(true); }}>
            neuer eintrag
          </button>
        </div>
      </div>

      <div className="table-responsive">
        <table className="table table-striped table-sm">
          <thead>
            <tr>
              <th>domain</th>
              <th>name</th>
              <th>typ</th>
              <th>ziel</th>
              <th>ttl</th>
              <th>dyn-dns</th>
              <th>aktionen</th>
            </tr>
          </thead>
          <tbody>
            {records.length === 0 && (
              <tr>
                <td colSpan={7} className="text-muted">noch keine daten</td>
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
                        setPendingKeys(prev => [...prev, key]);
                        try {
                          const res = await fetch(`/api/records`, { method: 'PATCH', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: r.domain, name: r.name, type: r.type, dyndns: newVal }) });
                          if (!res.ok) throw new Error('update failed');
                          const list = await getRecordsForDomain('AAAA', selectedDomain);
                          setRecords(list.records || []);
                        } catch (err) {
                          alert('Fehler beim Aktualisieren');
                        } finally {
                          setPendingKeys(prev => prev.filter(k => k !== key));
                        }
                      }} />
                    );
                  })()}
                </td>
                <td>
                  <button className="btn btn-sm btn-outline-secondary" onClick={async () => {
                    if (!confirm(`Lösche Eintrag ${r.name} ${r.type} -> ${r.content} ?`)) return;
                    setLoading(true);
                    try {
                      await fetch(`/api/records`, { method: 'DELETE', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(r) });
                      setRecords(prev => prev.filter(x => !(x.domain === r.domain && x.name === r.name && x.type === r.type && x.content === r.content)));
                    } catch (e: any) {
                      alert(e?.message || 'fehler beim löschen');
                    } finally {
                      setLoading(false);
                    }
                  }}>löschen</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <>
          <div className="modal-backdrop fade show" />
          <div className="modal d-block" tabIndex={-1}>
            <div className="modal-dialog">
                <div className="modal-content p-3">
                <div className="modal-header">
                  <h5 className="modal-title">neuer AAAA-Eintrag</h5>
                  <button className="btn-close" onClick={() => setShowModal(false)} />
                </div>
                <div className="modal-body">
                  <form onSubmit={async (e) => {
                    e.preventDefault();
                    if (!selectedDomain) { alert('Keine Domain ausgewählt'); return; }
                    const name = modalName.trim();
                    let content = modalContent.trim();
                    const ttlStr = modalTTL ?? '';
                    const ttl = ttlStr ? parseInt(ttlStr as string, 10) : undefined;
                    const dyndns = modalDyndns;
                    if (!name) { alert('Name darf nicht leer sein'); return; }
                    if (!content && !dyndns) { alert('Ziel darf nicht leer sein'); return; }
                    if (!ttlStr) { alert('TTL darf nicht leer sein'); return; }
                    if (isNaN(Number(ttl)) || (ttl !== undefined && ttl <= 0)) { alert('TTL muss eine positive ganze Zahl sein'); return; }
                    setLoading(true);
                    try {
                      const payload: any = { type: 'AAAA', name, content };
                      if (typeof ttl !== 'undefined') payload.ttl = ttl;
                      if (dyndns) payload.dyndns = true;
                      if (dyndns && content.toLowerCase() === 'auto') {
                        try {
                          const r = await fetch('https://api64.ipify.org?format=json');
                          if (r.ok) {
                            const j = await r.json();
                            payload.provider_content = j.ip;
                          }
                        } catch (e) {
                        }
                        payload.content = 'auto';
                      }

                      const res = await fetch(`/api/domains/${selectedDomain}/records`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
                      if (!res.ok) throw new Error((await res.json()).detail || 'fehler');
                      const body = await res.json();
                      setRecords(prev => [{ domain: selectedDomain, name, type: 'AAAA', content, ttl, dyndns }, ...prev]);
                      setShowModal(false);
                      alert(body.message || 'Eintrag erstellt');
                    } catch (err: any) {
                      alert(err?.message || 'fehler beim erstellen');
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
                      <input name="content" value={modalContent} onChange={e => setModalContent(e.target.value)} type="text" className="form-control" placeholder="2606:4700:4700::64" required disabled={modalDyndns} />
                    </div>
                    <div className="mb-3">
                      <label className="form-label">TTL (Sekunden)</label>
                      <input name="ttl" value={modalTTL ?? ''} onChange={e => setModalTTL(e.target.value)} type="number" className="form-control" placeholder="3600" disabled={modalDyndns} />
                    </div>
                    <div className="form-check mb-3">
                      <input name="dyndns" className="form-check-input" type="checkbox" id="dyndnsCheckAAAA" checked={modalDyndns} onChange={e => { const v = e.target.checked; setModalDyndns(v); if (v) { setModalContent('auto'); setModalTTL('60'); } else { setModalContent(''); setModalTTL(undefined); } }} />
                      <label className="form-check-label" htmlFor="dyndnsCheckAAAA">DynDNS aktiv (auto)</label>
                    </div>
                    <div className="d-flex justify-content-end">
                      <button type="button" className="btn btn-secondary me-2" onClick={() => setShowModal(false)}>abbrechen</button>
                      <button type="submit" className="btn btn-primary">erstellen</button>
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

export default AAAARecords;
