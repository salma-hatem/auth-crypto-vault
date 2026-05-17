// Tamper Demo Panel — bit flips → HMAC rejection

const { useState: useStateT, useEffect: useEffectT, useRef: useRefT, useMemo: useMemoT } = React;

function TamperScreen() {
  // Build a fixed visualization blob: 16 salt + 12 nonce + 96 ciphertext + 64 tag = 188 bytes shown in a grid
  const ORIG_SALT   = useMemo(() => randHex(16, 0xCAFEBABE), []);
  const ORIG_NONCE  = useMemo(() => randHex(12, 0xDEADBEEF), []);
  const ORIG_CT     = useMemo(() => randHex(96, 0xFEEDFACE), []);
  const ORIG_TAG    = useMemo(() => randHex(64, 0x1337C0DE), []);

  const [salt, setSalt]   = useStateT(ORIG_SALT);
  const [nonce, setNonce] = useStateT(ORIG_NONCE);
  const [ct, setCt]       = useStateT(ORIG_CT);
  const [tag, setTag]     = useStateT(ORIG_TAG);

  const [flipInfo, setFlipInfo] = useStateT(null); // {region, byteIdx, bitIdx}
  const [status, setStatus]   = useStateT(null);
  const [trying, setTrying]   = useStateT(false);
  const [highlight, setHighlight] = useStateT(null);
  const [step, setStep]       = useStateT(null); // 'recompute' | 'compare' | 'reject'

  // Flip one bit in a hex string
  function flipBit(hex, byteIdx, bitIdx) {
    const a = parseInt(hex.slice(byteIdx*2, byteIdx*2+2), 16);
    const flipped = a ^ (1 << bitIdx);
    return hex.slice(0, byteIdx*2) + flipped.toString(16).padStart(2, '0') + hex.slice(byteIdx*2 + 2);
  }

  function doFlip(region) {
    if (trying) return;
    let src, setSrc, len;
    if (region === 'salt')   { src = salt; setSrc = setSalt; len = 16; }
    if (region === 'nonce')  { src = nonce; setSrc = setNonce; len = 12; }
    if (region === 'cipher') { src = ct;   setSrc = setCt;   len = 96; }
    if (region === 'hmac')   { src = tag;  setSrc = setTag;  len = 64; }

    const byteIdx = Math.floor(Math.random() * len);
    const bitIdx  = Math.floor(Math.random() * 8);
    const flipped = flipBit(src, byteIdx, bitIdx);
    setSrc(flipped);
    setFlipInfo({ region, byteIdx, bitIdx });
    runVerify(`bit ${bitIdx} of ${region}[${byteIdx}]`);
  }

  function doWrongPassword() {
    if (trying) return;
    setFlipInfo({ region: 'password' });
    runVerify('wrong-password derives a different key → different HMAC');
  }

  function runVerify(label) {
    setTrying(true); setStatus(null); setStep('recompute'); setHighlight('all');
    setTimeout(() => {
      setStep('compare'); setHighlight('hmac');
      setTimeout(() => {
        setStep('reject');
        setStatus({
          kind: 'err',
          title: 'REJECTED — HMAC mismatch',
          body: `${label}. No plaintext produced. Vault treated as tampered.`,
        });
        setTrying(false);
      }, 900);
    }, 900);
  }

  function reset() {
    setSalt(ORIG_SALT); setNonce(ORIG_NONCE); setCt(ORIG_CT); setTag(ORIG_TAG);
    setFlipInfo(null); setStatus(null); setHighlight(null); setStep(null);
  }

  // Render bytes grid
  function ByteGrid() {
    // Combine into one array of 188 bytes
    const bytes = [];
    for (let i = 0; i < 16; i++) bytes.push({ region:'salt', hex: salt.slice(i*2, i*2+2), idx:i });
    for (let i = 0; i < 12; i++) bytes.push({ region:'nonce', hex: nonce.slice(i*2, i*2+2), idx:i });
    for (let i = 0; i < 96; i++) bytes.push({ region:'cipher', hex: ct.slice(i*2, i*2+2), idx:i });
    for (let i = 0; i < 64; i++) bytes.push({ region:'hmac', hex: tag.slice(i*2, i*2+2), idx:i });
    return (
      <div className="bytes-grid">
        {bytes.map((b, gi) => {
          const isFlipped = flipInfo && flipInfo.region === b.region && flipInfo.byteIdx === b.idx;
          return (
            <div key={gi}
              className={'byte ' + b.region + (isFlipped ? ' flipped' : '')}>
              {b.hex}
            </div>
          );
        })}
      </div>
    );
  }

  // Pretty bit display when a bit is flipped
  function BitFlipDetail() {
    if (!flipInfo || flipInfo.region === 'password') return null;
    const { region, byteIdx, bitIdx } = flipInfo;
    const src = region === 'salt' ? salt : region === 'nonce' ? nonce : region === 'cipher' ? ct : tag;
    const origSrc = region === 'salt' ? ORIG_SALT : region === 'nonce' ? ORIG_NONCE : region === 'cipher' ? ORIG_CT : ORIG_TAG;
    const before = parseInt(origSrc.slice(byteIdx*2, byteIdx*2+2), 16);
    const after  = parseInt(src.slice(byteIdx*2, byteIdx*2+2), 16);
    const bitsBefore = before.toString(2).padStart(8, '0').split('');
    const bitsAfter  = after.toString(2).padStart(8, '0').split('');
    return (
      <div className="card">
        <div className="card-title"><span className="num">BIT</span> Single bit flipped</div>
        <div style={{display:'grid', gridTemplateColumns:'auto 1fr', gap:'10px 14px', alignItems:'center'}}>
          <div className="label" style={{margin:0}}>Region</div>
          <div className="mono-pill" style={{color: region==='salt'?'var(--salt)':region==='nonce'?'var(--nonce)':region==='cipher'?'var(--cipher)':'var(--hmac)'}}>
            {region.toUpperCase()} · byte [{byteIdx}] · bit {bitIdx}
          </div>
          <div className="label" style={{margin:0}}>Before</div>
          <div className="bit-track">
            {bitsBefore.map((b, i) => (
              <div key={i} className={'bit ' + (b === '1' ? 'on' : '')}>{b}</div>
            ))}
          </div>
          <div className="label" style={{margin:0}}>After</div>
          <div className="bit-track">
            {bitsAfter.map((b, i) => {
              const flipped = b !== bitsBefore[i];
              return <div key={i} className={'bit ' + (b === '1' ? 'on ' : '') + (flipped ? 'flipped' : '')}>{b}</div>;
            })}
          </div>
          <div className="label" style={{margin:0}}>Bytes</div>
          <div style={{fontFamily:'var(--font-mono)', fontSize:12, color:'var(--ink-dim)'}}>
            0x{before.toString(16).padStart(2,'0')} → <span style={{color:'var(--warn)'}}>0x{after.toString(16).padStart(2,'0')}</span>
            &nbsp;·&nbsp;Hamming distance = 1
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="content">
      <div className="card">
        <div className="card-title">
          <span className="num">VAULT</span> Live byte view (188 B sample)
          <span style={{marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
            {flipInfo ? 'TAMPERED' : 'pristine'}
          </span>
        </div>
        <ByteGrid/>
        <div style={{display:'flex', gap:14, marginTop:10, fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
          <span><span style={{display:'inline-block', width:8, height:8, background:'var(--salt)', borderRadius:2, marginRight:5}}/>Salt</span>
          <span><span style={{display:'inline-block', width:8, height:8, background:'var(--nonce)', borderRadius:2, marginRight:5}}/>Nonce</span>
          <span><span style={{display:'inline-block', width:8, height:8, background:'var(--cipher)', borderRadius:2, marginRight:5}}/>Ciphertext</span>
          <span><span style={{display:'inline-block', width:8, height:8, background:'var(--hmac)', borderRadius:2, marginRight:5}}/>HMAC tag</span>
        </div>
      </div>

      <div className="grid-2" style={{marginTop:16}}>
        {/* LEFT */}
        <div className="col">
          <div className="card">
            <div className="card-title"><span className="num">ATTACK</span> Flip 1 bit in…</div>
            <div className="tamper-btns">
              <button className="btn salt"   onClick={() => doFlip('salt')}   disabled={trying}>
                <span className="lbl">REGION</span><span className="nm"><Icon name="flip" size={12}/> Salt</span>
              </button>
              <button className="btn nonce"  onClick={() => doFlip('nonce')}  disabled={trying}>
                <span className="lbl">REGION</span><span className="nm"><Icon name="flip" size={12}/> Nonce</span>
              </button>
              <button className="btn cipher" onClick={() => doFlip('cipher')} disabled={trying}>
                <span className="lbl">REGION</span><span className="nm"><Icon name="flip" size={12}/> Ciphertext</span>
              </button>
              <button className="btn hmac"   onClick={() => doFlip('hmac')}   disabled={trying}>
                <span className="lbl">REGION</span><span className="nm"><Icon name="flip" size={12}/> HMAC Tag</span>
              </button>
            </div>
            <div style={{display:'flex', gap:8, marginTop:10}}>
              <button className="btn" onClick={doWrongPassword} disabled={trying} style={{flex:1}}>
                <Icon name="alert" size={14} color="#fbbf24"/> Try wrong password
              </button>
              <button className="btn ghost" onClick={reset} disabled={trying}>
                <Icon name="reset" size={14}/> Reset blob
              </button>
            </div>
            <div style={{marginTop:12, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)', lineHeight:1.6}}>
              In all five cases below, the result is <strong style={{color:'var(--warn)'}}>identical</strong>:
              the HMAC check fails and decryption never runs. This is the core guarantee of authenticated encryption.
            </div>
          </div>

          <BitFlipDetail/>
        </div>

        {/* RIGHT */}
        <div className="col">
          <div className="card">
            <div className="card-title"><span className="num">VERIFY</span> Verification pipeline</div>
            <div style={{display:'flex', flexDirection:'column', gap:10}}>
              <div className={'pipeline-step ' + (step === 'recompute' ? 'active' : step ? 'done' : '')}>
                <div className="step-num">{step && step !== 'recompute' ? '✓' : '1'}</div>
                <div className="step-body">
                  <div className="step-name">Recompute HMAC over (salt ∥ nonce ∥ ct)</div>
                  <div className="step-desc">HMAC-SHA-512 with derived key k</div>
                </div>
                <div className="step-out">
                  {step === 'recompute' && <span className="spinner"/>}
                </div>
              </div>
              <div className={'pipeline-step ' + (step === 'compare' ? 'active' : step === 'reject' ? 'done' : '')}>
                <div className="step-num" style={step === 'reject' ? {background:'var(--warn)', color:'var(--on-warn)', borderColor:'var(--warn)'} : {}}>
                  {step === 'reject' ? '✗' : '2'}
                </div>
                <div className="step-body">
                  <div className="step-name">Compare to stored tag</div>
                  <div className="step-desc">hmac.compare_digest — constant-time</div>
                </div>
                <div className="step-out" style={step === 'reject' ? {color:'var(--warn)'} : {}}>
                  {step === 'reject' && 'mismatch'}
                  {step === 'compare' && <span className="spinner"/>}
                </div>
              </div>
              <div className={'pipeline-step ' + (step === 'reject' ? 'fail-step' : '')} style={step === 'reject' ? {opacity:1, borderColor:'var(--warn)', background:'var(--warn-bg)'} : {}}>
                <div className="step-num" style={step === 'reject' ? {background:'var(--warn)', color:'var(--on-warn)', borderColor:'var(--warn)'} : {}}>
                  {step === 'reject' ? '⊘' : '3'}
                </div>
                <div className="step-body">
                  <div className="step-name" style={step === 'reject' ? {color:'var(--warn)'} : {}}>Decrypt</div>
                  <div className="step-desc">never runs if step 2 fails</div>
                </div>
                <div className="step-out" style={step === 'reject' ? {color:'var(--warn)'} : {}}>
                  {step === 'reject' && 'blocked'}
                </div>
              </div>
            </div>
          </div>

          {status && (
            <div className={'status ' + status.kind}>
              <div className="st-icon">✗</div>
              <div>
                <div className="status-title">{status.title}</div>
                <div className="status-body">{status.body}</div>
              </div>
            </div>
          )}

          {!status && !flipInfo && (
            <div className="card" style={{borderStyle:'dashed'}}>
              <div style={{fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)', lineHeight:1.7}}>
                <strong style={{color:'var(--ink)'}}>Try this</strong>
                <ol style={{margin:'8px 0 0 18px', padding:0}}>
                  <li>Flip a bit in any region — the byte turns red.</li>
                  <li>Watch the verifier recompute the HMAC and compare.</li>
                  <li>See decryption be <em>blocked</em>, not just warned.</li>
                </ol>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

window.TamperScreen = TamperScreen;
