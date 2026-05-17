// Decrypt screen — calls /api/decrypt with real vault files

const { useState: useStateD, useEffect: useEffectD } = React;

function DecryptScreen({ backend }) {
  const [file, setFile] = useStateD(null);
  const [outName, setOutName] = useStateD('recovered.bin');
  const [password, setPassword] = useStateD('');
  const [running, setRunning] = useStateD(false);
  const [gate, setGate] = useStateD({ verify: 'idle', decrypt: 'idle' });
  const [status, setStatus] = useStateD(null);
  const [storedTag, setStoredTag] = useStateD(null);
  const [computedTag, setComputedTag] = useStateD(null);
  // Demo mode: load a pre-baked blob from the server
  const [demoBlob, setDemoBlob] = useStateD(null);
  const [scenario, setScenario] = useStateD(null); // null = real | 'correct'|'wrong'|'tamper'|'corrupt'

  useEffectD(() => {
    fetch('/api/demo').then(r => r.json()).then(setDemoBlob).catch(() => {});
  }, []);

  function reset() {
    setGate({ verify: 'idle', decrypt: 'idle' });
    setStatus(null);
    setStoredTag(null);
    setComputedTag(null);
  }

  // Build the FormData to send, applying the selected demo scenario if active
  async function buildFormData() {
    if (scenario && demoBlob) {
      let blobBytes = Uint8Array.from(atob(demoBlob.blob_b64), c => c.charCodeAt(0));
      let pw = demoBlob.password;
      if (scenario === 'wrong')   pw = pw + '_WRONG';
      if (scenario === 'tamper')  { blobBytes = new Uint8Array(blobBytes); blobBytes[28] ^= 0x01; }
      if (scenario === 'corrupt') blobBytes = blobBytes.slice(0, 20);
      const fd = new FormData();
      fd.append('file', new Blob([blobBytes]), 'demo.acv');
      fd.append('password', pw);
      fd.append('backend', backend);
      return fd;
    }
    if (!file) return null;
    const fd = new FormData();
    fd.append('file', file);
    fd.append('password', password);
    fd.append('backend', backend);
    return fd;
  }

  async function run() {
    reset();
    const fd = await buildFormData();
    if (!fd) return;

    setRunning(true);
    setGate({ verify: 'running', decrypt: 'idle' });

    let data;
    try {
      const resp = await fetch('/api/decrypt', { method: 'POST', body: fd });
      data = await resp.json();
    } catch (e) {
      setStatus({
        kind: 'err',
        title: 'Cannot reach the server',
        body: 'Make sure the server is running:  python gui/server.py\n\n(' + String(e) + ')',
      });
      setRunning(false);
      return;
    }

    setStoredTag(data.stored_tag || null);
    setComputedTag(data.computed_tag || null);

    if (data.success) {
      setGate({ verify: 'pass', decrypt: 'running' });
      setTimeout(() => {
        setGate({ verify: 'pass', decrypt: 'pass' });
        setStatus({
          kind: 'ok',
          title: 'Decryption successful',
          body: `Recovered ${formatBytes(data.plain_size)} — downloading as "${outName}"`,
        });
        // download via direct link (no base64 in memory)
        const a = document.createElement('a');
        a.href = `/api/download/${data.download_token}`;
        a.download = outName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setRunning(false);
      }, 700);
    } else {
      setGate({ verify: 'fail', decrypt: 'blocked' });
      setStatus({
        kind: data.error.includes('too short') ? 'warn' : 'err',
        title: data.error.includes('too short')
          ? 'Structural error — vault truncated'
          : 'SECURITY WARNING — HMAC verification failed',
        body: data.error + (data.error.includes('tampered') ? ' (Identical error for tampered file and wrong password — no information leak by design.)' : ''),
      });
      setRunning(false);
    }
  }

  const sameTag = storedTag && computedTag && storedTag === computedTag;
  const canRun = !running && (scenario ? !!demoBlob : !!file);

  return (
    <div className="content">
      <div className="grid-2">
        {/* LEFT */}
        <div className="col">
          <div className="card">
            <div className="card-title"><span className="num">01</span> Vault file</div>
            <DropZone kind="vault" file={scenario ? {name:'demo.acv', size: demoBlob ? atob(demoBlob.blob_b64).length : 0} : file} onFile={f => { setFile(f); setScenario(null); }} accept=".acv"/>
          </div>
          <div className="card">
            <div className="card-title"><span className="num">02</span> Output filename</div>
            <input className="text-input" value={outName} onChange={e => setOutName(e.target.value)} placeholder="recovered.bin"/>
          </div>
          <div className="card">
            <div className="card-title"><span className="num">03</span> Passphrase</div>
            <PasswordInput value={scenario ? (scenario === 'wrong' ? demoBlob?.password + '_WRONG' : demoBlob?.password || '') : password} onChange={v => { setPassword(v); setScenario(null); }} placeholder={scenario ? '(demo password)' : 'enter passphrase…'}/>
          </div>

          <div className="card">
            <div className="card-title"><span className="num">DEMO</span> Simulate scenario</div>
            <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:8}}>
              {[
                { id:'correct', label:'Correct password', kind:'ok' },
                { id:'wrong',   label:'Wrong password',   kind:'err' },
                { id:'tamper',  label:'Tampered byte',    kind:'err' },
                { id:'corrupt', label:'Truncated file',   kind:'warn' },
              ].map(s => (
                <button
                  key={s.id}
                  className={'btn ' + (scenario === s.id ? (s.kind === 'ok' ? 'success' : s.kind === 'err' ? 'danger' : '') : 'ghost')}
                  onClick={() => { setScenario(s.id); reset(); }}
                  disabled={running}
                  style={{padding:'10px', fontSize:12}}>
                  {scenario === s.id && '● '}{s.label}
                </button>
              ))}
            </div>
            <div style={{marginTop:10, fontSize:11, color:'var(--ink-mute)', fontFamily:'var(--font-mono)'}}>
              Selects a pre-baked demo blob — runs through the real Python backend.
            </div>
          </div>

          <button className="btn primary lg" onClick={run} disabled={!canRun}>
            {running ? <><span className="spinner"/> Decrypting…</> : <><Icon name="unlock" size={15}/> Decrypt vault</>}
            <span className="kbd">⏎</span>
          </button>
        </div>

        {/* RIGHT — gate animation */}
        <div className="col">
          <div className="card">
            <div className="card-title">
              <span className="num">→</span> Verify-then-decrypt
              <span style={{marginLeft:'auto', fontSize:10, color:'var(--ink-mute)', fontFamily:'var(--font-mono)'}}>
                Step 2 cannot run if Step 1 fails
              </span>
            </div>

            <div className="gate-flow">
              <div className={'gate-stage ' + gate.verify}>
                <div className="stage-num">STEP 1</div>
                <div className="stage-title">Verify HMAC</div>
                <div className="stage-sub">recompute HMAC(k, salt∥nonce∥ct) → compare to stored tag (constant-time)</div>
                <div style={{marginTop:10}}>
                  {gate.verify === 'idle'    && <span className="mono-pill">awaiting input</span>}
                  {gate.verify === 'running' && <span className="mono-pill" style={{color:'var(--accent)'}}><span className="spinner" style={{display:'inline-block', verticalAlign:'middle', marginRight:6}}/> hashing…</span>}
                  {gate.verify === 'pass'    && <span className="mono-pill" style={{color:'var(--ok)'}}>✓ tags match</span>}
                  {gate.verify === 'fail'    && <span className="mono-pill" style={{color:'var(--warn)'}}>✗ mismatch — abort</span>}
                </div>
              </div>

              <div className={'gate-arrow ' +
                (gate.verify === 'running' ? 'flow' :
                 gate.verify === 'pass' && gate.decrypt !== 'idle' ? 'passed' :
                 gate.verify === 'fail' ? 'blocked' : '')}>
                {gate.verify === 'fail' ? '⊘' : '→'}
              </div>

              <div className={'gate-stage ' + gate.decrypt}>
                <div className="stage-num">STEP 2</div>
                <div className="stage-title">AES-128-CTR decrypt</div>
                <div className="stage-sub">{backend === 'v2' ? 'T-table backend (C)' : 'pure-Python AES core'} · keystream XOR</div>
                <div style={{marginTop:10}}>
                  {gate.decrypt === 'idle'    && <span className="mono-pill">waiting on verify</span>}
                  {gate.decrypt === 'blocked' && <span className="mono-pill" style={{color:'var(--warn)'}}>blocked — never executed</span>}
                  {gate.decrypt === 'running' && <span className="mono-pill" style={{color:'var(--accent)'}}><span className="spinner" style={{display:'inline-block', verticalAlign:'middle', marginRight:6}}/> XOR'ing keystream…</span>}
                  {gate.decrypt === 'pass'    && <span className="mono-pill" style={{color:'var(--ok)'}}>✓ plaintext written</span>}
                </div>
              </div>
            </div>
          </div>

          {(storedTag || computedTag) && (
            <div className="card">
              <div className="card-title"><span className="num">CMP</span> Tag comparison (real values)</div>
              <div style={{display:'flex', flexDirection:'column', gap:8}}>
                <div>
                  <div className="label">Stored tag (from vault blob)</div>
                  <div style={{fontFamily:'var(--font-mono)', fontSize:11, color:'var(--hmac)', wordBreak:'break-all', background:'var(--bg-2)', borderRadius:6, padding:'8px 10px'}}>
                    {storedTag || '…'}
                  </div>
                </div>
                <div>
                  <div className="label">Recomputed tag</div>
                  <div style={{fontFamily:'var(--font-mono)', fontSize:11, color: sameTag ? 'var(--ok)' : 'var(--warn)', wordBreak:'break-all', background:'var(--bg-2)', border:'1px solid ' + (sameTag ? 'var(--ok)' : 'var(--warn)'), borderRadius:6, padding:'8px 10px'}}>
                    {computedTag || '—'}
                  </div>
                </div>
                {computedTag && storedTag && (
                  <div style={{fontFamily:'var(--font-mono)', fontSize:11}}>
                    {sameTag
                      ? <span style={{color:'var(--ok)'}}>✓ hmac_equal(stored, computed) → True</span>
                      : <span style={{color:'var(--warn)'}}>✗ hmac_equal(stored, computed) → False</span>}
                  </div>
                )}
              </div>
            </div>
          )}

          {status && (
            <div className={'status ' + status.kind}>
              <div className="st-icon">{status.kind === 'ok' ? '✓' : status.kind === 'warn' ? '!' : '✗'}</div>
              <div>
                <div className="status-title">{status.title}</div>
                <div className="status-body">{status.body}</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

window.DecryptScreen = DecryptScreen;
