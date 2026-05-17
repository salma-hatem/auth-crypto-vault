// Encrypt screen — calls /api/encrypt

const { useState: useStateE, useEffect: useEffectE, useRef: useRefE } = React;

function EncryptScreen({ backend }) {
  const [file, setFile] = useStateE(null);
  const [outName, setOutName] = useStateE('output.acv');
  const [password, setPassword] = useStateE('');
  const [running, setRunning] = useStateE(false);
  const [step, setStep] = useStateE(-1);
  const [blob, setBlob] = useStateE(null);
  const [status, setStatus] = useStateE(null);
  const [stepResults, setStepResults] = useStateE([]);
  const [highlight, setHighlight] = useStateE(null);

  const steps = [
    { name: '1. Generate salt',        desc: 'os.urandom(16)' },
    { name: '2. Derive key',           desc: 'k = SHA-512(password ∥ salt)[:16]' },
    { name: '3. Generate nonce',       desc: 'os.urandom(12)' },
    { name: '4. AES-128-CTR encrypt',  desc: backend === 'v2' ? 'T-table backend (C)' : 'Pure-Python AES' },
    { name: '5. HMAC-SHA-512',         desc: 'HMAC(k, salt ∥ nonce ∥ ct)' },
    { name: '6. Assemble vault blob',  desc: 'salt ∥ nonce ∥ ct ∥ tag' },
  ];
  const highlights = ['salt', null, 'nonce', 'cipher', 'hmac', null];
  // animation delays per step (ms) — cosmetic while API call is in flight
  const delays = [400, 500, 400, backend === 'v2' ? 600 : 1000, 500, 350];

  const ready = file && password.length >= 1 && !running;

  async function run() {
    setRunning(true);
    setStep(0);
    setBlob(null);
    setStatus(null);
    setStepResults([]);
    setHighlight(null);

    // fire API call immediately
    const formData = new FormData();
    formData.append('file', file);
    formData.append('password', password);
    formData.append('backend', backend);
    const fetchPromise = fetch('/api/encrypt', { method: 'POST', body: formData });

    // cosmetic pipeline animation while waiting
    const placeholders = [
      trueRandHex(16),
      '(derived from password + salt)',
      trueRandHex(12),
      '…',
      '…',
      `blob = ${16 + 12 + file.size + 64} B`,
    ];
    for (let i = 0; i < steps.length; i++) {
      setStep(i);
      setStepResults(r => { const nr = [...r]; nr[i] = placeholders[i]; return nr; });
      setHighlight(highlights[i]);
      await new Promise(r => setTimeout(r, delays[i]));
    }

    // settle API result
    let data;
    try {
      const resp = await fetchPromise;
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

    if (data.success) {
      // fill in real values from backend
      setStepResults(r => {
        const nr = [...r];
        nr[0] = data.salt;
        nr[2] = data.nonce;
        nr[3] = '0x' + data.ciphertext_preview + (data.plain_size > 64 ? '…' : '');
        nr[4] = data.tag.slice(0, 32) + '…';
        return nr;
      });
      setBlob({
        salt: data.salt,
        nonce: data.nonce,
        ciphertext: data.ciphertext_preview + (data.plain_size > 64 ? '…' : ''),
        tag: data.tag,
        plainSize: data.plain_size,
      });
      setStatus({
        kind: 'ok',
        title: 'Encryption successful',
        body: `${formatBytes(data.blob_size)} vault blob ready — downloading as "${outName}"`,
      });
      // download via direct link (no base64 in memory — works for any file size)
      const a = document.createElement('a');
      a.href = `/api/download/${data.download_token}`;
      a.download = outName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } else {
      setStatus({ kind: 'err', title: 'Encryption failed', body: data.error });
    }

    setStep(steps.length);
    setHighlight(null);
    setRunning(false);
  }

  function reset() {
    setFile(null);
    setPassword('');
    setBlob(null);
    setStatus(null);
    setStep(-1);
    setStepResults([]);
    setHighlight(null);
  }

  return (
    <div className="content">
      <div className="grid-2">
        {/* LEFT — Inputs */}
        <div className="col">
          <div className="card">
            <div className="card-title"><span className="num">01</span> Input</div>
            <label className="label">Plaintext file</label>
            <DropZone kind="plain" file={file} onFile={setFile}/>
          </div>

          <div className="card">
            <div className="card-title"><span className="num">02</span> Output</div>
            <label className="label">Output filename (saved to Downloads)</label>
            <input
              className="text-input"
              value={outName}
              onChange={e => setOutName(e.target.value)}
              placeholder="output.acv"
            />
          </div>

          <div className="card">
            <div className="card-title"><span className="num">03</span> Passphrase</div>
            <PasswordInput value={password} onChange={setPassword}/>
            <div style={{display:'flex', gap:8, marginTop:10, alignItems:'center', fontSize:11, color:'var(--ink-mute)', fontFamily:'var(--font-mono)'}}>
              <Icon name="shield" size={12} color="#9aa7b8"/>
              <span>Stretched via SHA-512 KDF · never stored · never displayed</span>
            </div>
          </div>

          <div style={{display:'flex', gap:10}}>
            <button className="btn primary lg" style={{flex:1}} disabled={!ready} onClick={run}>
              {running
                ? <><span className="spinner"/> Encrypting…</>
                : <><Icon name="lock" size={15}/> Encrypt vault</>}
              <span className="kbd">⏎</span>
            </button>
            <button className="btn ghost lg" onClick={reset} disabled={running}>
              <Icon name="reset" size={14}/> Reset
            </button>
          </div>
        </div>

        {/* RIGHT — Live pipeline */}
        <div className="col">
          <div className="card">
            <div className="card-title">
              <span className="num">→</span> Live encryption pipeline
              {running && <span style={{marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:10, color:'var(--accent)'}}>● RUNNING</span>}
            </div>
            <Pipeline steps={steps} current={step} results={stepResults}/>
          </div>

          {running && step === 3 && (
            <div className="card">
              <div className="card-title"><span className="num">CTR</span> Keystream → XOR plaintext</div>
              <HexStream active={true} color="cipher" tick={120}/>
            </div>
          )}

          {status && (
            <div className={'status ' + status.kind}>
              <div className="st-icon">{status.kind === 'ok' ? '✓' : '!'}</div>
              <div>
                <div className="status-title">{status.title}</div>
                <div className="status-body">{status.body}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* BOTTOM — Blob anatomy */}
      <div className="card" style={{marginTop:16}}>
        <div className="card-title">
          <span className="num">VAULT</span> Output blob anatomy
          <span style={{marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
            {blob ? `${16 + 12 + blob.plainSize + 64} bytes total` : 'awaiting encryption'}
          </span>
        </div>
        <BlobAnatomy blob={blob} highlight={highlight}/>
        {!blob && (
          <div style={{marginTop:12, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)'}}>
            Run an encryption to populate. Layout:&nbsp;
            <span style={{color:'var(--salt)'}}>[ salt 16B ]</span>&nbsp;
            <span style={{color:'var(--nonce)'}}>[ nonce 12B ]</span>&nbsp;
            <span style={{color:'var(--cipher)'}}>[ ciphertext NB ]</span>&nbsp;
            <span style={{color:'var(--hmac)'}}>[ tag 64B ]</span>
          </div>
        )}
      </div>
    </div>
  );
}

window.EncryptScreen = EncryptScreen;
