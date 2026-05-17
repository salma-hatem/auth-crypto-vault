// Shared helpers and components

const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ---------- Hex helpers ----------
const HEX = '0123456789abcdef';
function randHex(bytes, seed) {
  let s = seed || 1;
  let out = '';
  for (let i = 0; i < bytes; i++) {
    s = (s * 1664525 + 1013904223) & 0xffffffff;
    const v = (s >>> 0) & 0xff;
    out += HEX[v >> 4] + HEX[v & 0xf];
  }
  return out;
}
function trueRandHex(bytes) {
  const u = new Uint8Array(bytes);
  crypto.getRandomValues(u);
  let out = '';
  for (let i = 0; i < bytes; i++) out += HEX[u[i] >> 4] + HEX[u[i] & 0xf];
  return out;
}
function truncHex(hex, frontBytes = 6, backBytes = 6) {
  if (hex.length <= (frontBytes + backBytes) * 2 + 4) return hex;
  return hex.slice(0, frontBytes * 2) + '…' + hex.slice(-backBytes * 2);
}
function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / (1024 * 1024)).toFixed(2) + ' MB';
}

// ---------- Icons (tiny inline SVGs) ----------
function Icon({ name, size = 16, color = 'currentColor' }) {
  const props = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: color, strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' };
  switch (name) {
    case 'lock':
      return <svg {...props}><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>;
    case 'unlock':
      return <svg {...props}><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7-2"/></svg>;
    case 'cpu':
      return <svg {...props}><rect x="6" y="6" width="12" height="12" rx="1"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M1 9h3M1 15h3M20 9h3M20 15h3"/></svg>;
    case 'gauge':
      return <svg {...props}><path d="M12 13l3-3"/><path d="M3 17a9 9 0 1 1 18 0"/></svg>;
    case 'alert':
      return <svg {...props}><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/></svg>;
    case 'eye':
      return <svg {...props}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="2.5"/></svg>;
    case 'eye-off':
      return <svg {...props}><path d="M9.9 4.24A10.5 10.5 0 0 1 12 4c6.5 0 10 7 10 7a18 18 0 0 1-2.16 3.19M6.6 6.6A18 18 0 0 0 2 12s3.5 7 10 7a10.5 10.5 0 0 0 5.4-1.6"/><path d="M1 1l22 22"/></svg>;
    case 'file':
      return <svg {...props}><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>;
    case 'check':
      return <svg {...props}><path d="M4 12l5 5L20 6"/></svg>;
    case 'x':
      return <svg {...props}><path d="M6 6l12 12M18 6L6 18"/></svg>;
    case 'play':
      return <svg {...props} fill={color} stroke="none"><path d="M6 4v16l14-8z"/></svg>;
    case 'reset':
      return <svg {...props}><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>;
    case 'flip':
      return <svg {...props}><path d="M3 12h18"/><path d="M17 8l4 4-4 4"/><path d="M7 16l-4-4 4-4"/></svg>;
    case 'shield':
      return <svg {...props}><path d="M12 2 4 6v6c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6l-8-4z"/></svg>;
    case 'arrow':
      return <svg {...props}><path d="M5 12h14"/><path d="M13 6l6 6-6 6"/></svg>;
    case 'folder':
      return <svg {...props}><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>;
    case 'sun':
      return <svg {...props}><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>;
    case 'moon':
      return <svg {...props}><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>;
    case 'download':
      return <svg {...props}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>;
    default: return null;
  }
}

// ---------- Backend Switch ----------
function BackendSwitch({ value, onChange }) {
  const [showTip, setShowTip] = useState(false);
  return (
    <div className="tooltip-host"
      onMouseEnter={() => setShowTip(true)}
      onMouseLeave={() => setShowTip(false)}>
      <div className="backend-switch">
        <button className={value === 'v1' ? 'on' : ''} onClick={() => onChange('v1')}>V1 · Pure Python</button>
        <button className={value === 'v2' ? 'on' : ''} onClick={() => onChange('v2')}>V2 · T-tables / C</button>
      </div>
      {showTip && (
        <div className="tooltip">
          <strong style={{color:'var(--ink)'}}>V2 backend</strong> uses the 4×T-table AES approach via a C shared library, ~100–300× faster than the pure-Python V1. Falls back to a Python T-table impl if the .so isn't built.
        </div>
      )}
    </div>
  );
}

// ---------- Drop zone (real file input) ----------
function DropZone({ kind, file, onFile, accept }) {
  const [drag, setDrag] = useState(false);
  const inputRef = useRef(null);

  function handleFiles(files) {
    if (files && files[0]) onFile(files[0]);
  }

  return (
    <div
      className={'dropzone ' + (drag ? 'dragover ' : '') + (file ? 'has-file' : '')}
      onDragOver={e => { e.preventDefault(); setDrag(true); }}
      onDragLeave={() => setDrag(false)}
      onDrop={e => { e.preventDefault(); setDrag(false); handleFiles(e.dataTransfer.files); }}
      onClick={() => inputRef.current && inputRef.current.click()}>
      <input
        ref={inputRef}
        type="file"
        accept={accept || '*'}
        style={{display: 'none'}}
        onChange={e => handleFiles(e.target.files)}
      />
      {file ? (
        <div>
          <div className="file-tag">
            <Icon name="file" size={14} color="#2dd4bf"/>
            <span>{file.name}</span>
            <span className="sz">{formatBytes(file.size)}</span>
          </div>
          <div className="dz-sub" style={{marginTop:8}}>Click or drop another file to replace</div>
        </div>
      ) : (
        <>
          <div className="dz-icon">
            <Icon name={kind === 'plain' ? 'file' : 'lock'} size={22} color="#9aa7b8"/>
          </div>
          <div className="dz-title">{kind === 'plain' ? 'Drop a file to encrypt' : 'Drop a .acv vault file'}</div>
          <div className="dz-sub">or click to browse · {accept || 'any file'}</div>
        </>
      )}
    </div>
  );
}

// ---------- Password input ----------
function PasswordInput({ value, onChange, placeholder = 'enter passphrase…' }) {
  const [shown, setShown] = useState(false);
  return (
    <div className="input-group">
      <input
        className="text-input"
        type={shown ? 'text' : 'password'}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{paddingRight: 60}}/>
      <button className="eye" onClick={() => setShown(s => !s)} aria-label="toggle">
        <Icon name={shown ? 'eye-off' : 'eye'} size={14}/>
      </button>
    </div>
  );
}

// ---------- Blob Anatomy ----------
function BlobAnatomy({ blob, highlight }) {
  const totalBytes = 16 + 12 + (blob?.plainSize || 0) + 64;
  const cipherBytes = blob?.plainSize || 0;
  const minPct = 6;
  const saltPct  = Math.max(minPct, 16 / totalBytes * 100);
  const noncePct = Math.max(minPct, 12 / totalBytes * 100);
  const tagPct   = Math.max(minPct, 64 / totalBytes * 100);
  let cipherPct  = 100 - saltPct - noncePct - tagPct;
  if (cipherPct < 20) cipherPct = 20;
  const total = saltPct + noncePct + cipherPct + tagPct;
  const ns = saltPct/total*100, nn = noncePct/total*100, nc = cipherPct/total*100, nt = tagPct/total*100;

  return (
    <div className="blob-anatomy">
      <div className="blob-bar">
        <div className={'blob-seg salt '  + (highlight==='salt'  ?'flash':'')} style={{flex: ns}}>SALT · 16 B</div>
        <div className={'blob-seg nonce ' + (highlight==='nonce' ?'flash':'')} style={{flex: nn}}>NONCE · 12 B</div>
        <div className={'blob-seg cipher '+ (highlight==='cipher'?'flash':'')} style={{flex: nc}}>CIPHERTEXT · {formatBytes(cipherBytes)}</div>
        <div className={'blob-seg hmac '  + (highlight==='hmac'  ?'flash':'')} style={{flex: nt}}>HMAC TAG · 64 B</div>
      </div>
      <div className="blob-legend">
        {[
          { cls:'salt',   label:'Salt',             sz:'16 B',             val: blob?.salt },
          { cls:'nonce',  label:'Nonce',            sz:'12 B',             val: blob?.nonce },
          { cls:'cipher', label:'Ciphertext',       sz:formatBytes(cipherBytes), val: blob ? truncHex(blob.ciphertext, 8, 8) : null, dim:true },
          { cls:'hmac',   label:'HMAC-SHA-512 Tag', sz:'64 B',             val: blob ? truncHex(blob.tag, 10, 10) : null },
        ].map(({ cls, label, sz, val, dim }) => (
          <div key={cls} className={'legend-item ' + cls + ' ' + (highlight===cls?'flash':'')}>
            <div className="legend-name"><span>{label}</span><span className="sz">{sz}</span></div>
            <div className={'legend-hex' + (dim?' dim':'')}>{val || '…'}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------- Hex stream (rolling) ----------
function HexStream({ active, lineLen = 32, lines = 4, color = 'cipher', tick = 100 }) {
  const [rows, setRows] = useState(() => Array.from({length: lines}, () => trueRandHex(lineLen/2)));
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => {
      setRows(r => [...r.slice(1), trueRandHex(lineLen/2)]);
    }, tick);
    return () => clearInterval(t);
  }, [active, tick, lineLen]);
  const c = color === 'cipher' ? 'var(--cipher)' : color === 'salt' ? 'var(--salt)' : color === 'nonce' ? 'var(--nonce)' : color === 'hmac' ? 'var(--hmac)' : 'var(--ink)';
  return (
    <div className="hex-stream">
      {rows.map((r, i) => (
        <div className="row" key={i} style={{color: c}}>{r}</div>
      ))}
    </div>
  );
}

// ---------- Pipeline (multi-step animator) ----------
function Pipeline({ steps, current, results }) {
  return (
    <div className="pipeline">
      {steps.map((s, i) => {
        const state = current > i ? 'done' : current === i ? 'active' : 'idle';
        return (
          <div key={i} className={'pipeline-step ' + state}>
            <div className="step-num">{state === 'done' ? '✓' : i+1}</div>
            <div className="step-body">
              <div className="step-name">{s.name}</div>
              <div className="step-desc">{s.desc}</div>
            </div>
            <div className="step-out">{state !== 'idle' && results[i]}</div>
          </div>
        );
      })}
    </div>
  );
}

// expose to all screens
Object.assign(window, {
  Icon, BackendSwitch, DropZone, PasswordInput, BlobAnatomy, HexStream, Pipeline,
  randHex, trueRandHex, truncHex, formatBytes,
});
