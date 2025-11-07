import React from 'react';

const overlayStyle: React.CSSProperties = {
  position: 'fixed',
  top: 0,
  left: 0,
  width: '100%',
  height: '100%',
  backgroundColor: 'rgba(0,0,0,0.4)',
  zIndex: 2000,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
};

export default function LoadingOverlay({ visible, text = 'Bitte warten…' }: { visible: boolean; text?: string }) {
  if (!visible) return null;
  return (
    <div style={overlayStyle} aria-hidden>
      <div className="text-center text-white">
        <div className="spinner-border text-light" role="status" style={{ width: '3rem', height: '3rem' }}>
          <span className="visually-hidden">Loading...</span>
        </div>
        <div className="mt-2">{text}</div>
      </div>
    </div>
  );
}
