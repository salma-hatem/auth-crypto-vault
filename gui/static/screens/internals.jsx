// Internals screen — real KDF via /api/kdf, real NIST badges via /api/nist

const { useState: useStateI, useEffect: useEffectI, useMemo: useMemoI } = React;

function InternalsScreen({ backend }) {
  const [password, setPassword] = useStateI('correct-horse-battery-staple');
  const [salt, setSalt] = useStateI(() => trueRandHex(16));
  const [nonce, setNonce] = useStateI(() => trueRandHex(12));
  const [counter, setCounter] = useStateI(0);
  const [autoCount, setAutoCount] = useStateI(true);
  const [derivedKey, setDerivedKey] = useStateI(null);
  const [nistTests, setNistTests] = useStateI(null);

  // Fetch real derived key whenever password/salt changes
  useEffectI(() => {
    if (!salt || salt.length !== 32) return;
    const ctrl = new AbortController();
    fetch('/api/kdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, salt }),
      signal: ctrl.signal,
    })
      .then(r => r.json())
      .then(d => { if (d.key) setDerivedKey(d.key); })
      .catch(() => {});
    return () => ctrl.abort();
  }, [password, salt]);

  // Fetch real NIST test results once on mount
  useEffectI(() => {
    fetch('/api/nist')
      .then(r => r.json())
      .then(d => setNistTests(d.tests))
      .catch(() => {});
  }, []);

  // Visual HMAC tag (illustrative — derived from visual key)
  const visualTag = useMemoI(() => {
    const seed = (password.length + salt.length + nonce.length + 99) * 2654435761;
    return randHex(64, seed | 0);
  }, [password, salt, nonce]);

  // XOR visualisation
  const ptBlock = '48656c6c6f20576f726c64210a000000';
  const keystream = useMemoI(() => randHex(16, (counter * 17 + nonce.length * 31) | 0), [counter, nonce]);
  const ctBlock = useMemoI(() => {
    let out = '';
    for (let i = 0; i < ptBlock.length; i += 2) {
      const a = parseInt(ptBlock.slice(i, i+2), 16);
      const b = parseInt(keystream.slice(i, i+2), 16);
      out += (a ^ b).toString(16).padStart(2, '0');
    }
    return out;
  }, [keystream]);

  useEffectI(() => {
    if (!autoCount) return;
    const t = setInterval(() => setCounter(c => (c + 1) >>> 0), 1100);
    return () => clearInterval(t);
  }, [autoCount]);

  const counterHex = counter.toString(16).padStart(8, '0');
  const displayKey = derivedKey || randHex(16, (password.length + salt.length) * 2654435761 | 0);

  return (
    <div className="content">
      <div className="grid-2">
        {/* LEFT */}
        <div className="col">
          {/* KDF */}
          <div className="card">
            <div className="card-title"><span className="num">①</span> Key derivation (KDF)</div>
            <div className="formula">
              <span className="kw">k</span> = SHA-512(<span className="pwd">password</span> ∥ <span className="salt">salt</span>)[:16]
            </div>
            <div style={{display:'grid', gap:10, marginTop:12}}>
              <div>
                <div className="label">Password (utf-8)</div>
                <input className="text-input" value={password} onChange={e => setPassword(e.target.value)}/>
              </div>
              <div>
                <div className="label">Salt (16 B, hex)</div>
                <div style={{display:'flex', gap:8}}>
                  <input className="text-input" value={salt} onChange={e => setSalt(e.target.value)} style={{color:'var(--salt)'}}/>
                  <button className="btn ghost" onClick={() => setSalt(trueRandHex(16))} title="Re-roll salt"><Icon name="reset" size={14}/></button>
                </div>
              </div>
              <div>
                <div className="label">Derived AES-128 key (k) {derivedKey ? '— real' : '— visual'}</div>
                <div style={{fontFamily:'var(--font-mono)', fontSize:12, padding:'10px 12px', background:'var(--bg-2)', borderRadius:8, color:'var(--accent)', wordBreak:'break-all'}}>
                  {displayKey}
                </div>
                <div style={{marginTop:6, fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
                  truncated to 16 B (128 bits) for AES-128 · re-derives on every encrypt/decrypt
                </div>
              </div>
            </div>
          </div>

          {/* HMAC */}
          <div className="card">
            <div className="card-title"><span className="num">②</span> HMAC-SHA-512 tag</div>
            <div className="formula">
              <span className="hmac">tag</span> = HMAC<sub>k</sub>(<span className="salt">salt</span> ∥ <span className="nonce">nonce</span> ∥ <span className="cipher">ciphertext</span>)
            </div>
            <div style={{marginTop:12}}>
              <div className="label">Illustrative tag (64 B)</div>
              <div style={{fontFamily:'var(--font-mono)', fontSize:11, padding:'10px 12px', background:'var(--bg-2)', borderLeft:'3px solid var(--hmac)', borderRadius:8, color:'var(--hmac)', wordBreak:'break-all', lineHeight:1.5}}>
                {visualTag}
              </div>
              <div style={{marginTop:8, fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)', lineHeight:1.6}}>
                HMAC inner = SHA-512( (k⊕ipad) ∥ msg )<br/>
                HMAC outer = SHA-512( (k⊕opad) ∥ inner )<br/>
                Compared with hmac_equal — constant-time, no early-exit.
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT */}
        <div className="col">
          {/* AES-CTR */}
          <div className="card">
            <div className="card-title">
              <span className="num">③</span> AES-128-CTR encryption
              <span style={{marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
                backend: <strong style={{color:backend === 'v2' ? 'var(--hmac)' : 'var(--nonce)'}}>{backend.toUpperCase()}</strong>
              </span>
            </div>

            <div className="label">Counter block construction (16 B)</div>
            <div className="counter-vis">
              <div className="nonce-part">
                <span className="lbl">Nonce · 12 B</span>
                <div style={{wordBreak:'break-all'}}>{nonce}</div>
              </div>
              <div className="counter-part">
                <span className="lbl">Counter · 4 B</span>
                <div style={{fontWeight:700, letterSpacing:'0.05em'}}>{counterHex}</div>
              </div>
            </div>
            <div style={{display:'flex', alignItems:'center', gap:8, marginTop:8, fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
              <button className="btn ghost" onClick={() => setAutoCount(a => !a)} style={{padding:'4px 8px', fontSize:10}}>
                {autoCount ? '⏸ Pause' : '▶ Resume'}
              </button>
              <button className="btn ghost" onClick={() => setCounter(0)} style={{padding:'4px 8px', fontSize:10}}>↺ Reset</button>
              <span>counter increments per 16-byte block · big-endian uint32</span>
            </div>

            <div style={{marginTop:14}} className="label">Per-block XOR</div>
            <div className="xor-vis">
              <div>
                <span className="lbl">Plaintext block</span>
                <div className="row pt">{ptBlock.match(/.{2}/g).join(' ')}</div>
              </div>
              <div className="op">⊕</div>
              <div>
                <span className="lbl">Keystream = AES(k, ctr)</span>
                <div className="row ks">{keystream.match(/.{2}/g).join(' ')}</div>
              </div>
              <div className="op">=</div>
              <div>
                <span className="lbl">Ciphertext block</span>
                <div className="row ct">{ctBlock.match(/.{2}/g).join(' ')}</div>
              </div>
            </div>
            <div style={{marginTop:8, fontFamily:'var(--font-mono)', fontSize:10, color:'var(--ink-mute)'}}>
              CTR turns a block cipher into a stream cipher — no padding, parallelisable, malleable (which is exactly why we MAC).
            </div>
          </div>

          {/* NIST tests */}
          <div className="card">
            <div className="card-title">
              <span className="num">④</span> NIST / RFC test vectors
              <span style={{marginLeft:'auto', fontFamily:'var(--font-mono)', fontSize:10, color: nistTests ? (nistTests.every(t => t.pass) ? 'var(--ok)' : 'var(--warn)') : 'var(--ink-mute)'}}>
                {nistTests ? `${nistTests.filter(t=>t.pass).length} / ${nistTests.length} passing` : 'loading…'}
              </span>
            </div>
            <div className="nist-row">
              {nistTests ? nistTests.map((t, i) => (
                <div key={i} className="nist-badge">
                  <div className="check" style={t.pass ? {} : {background:'var(--warn)', color:'var(--on-warn)'}}>
                    {t.pass ? '✓' : '✗'}
                  </div>
                  <div className="nist-name">{t.label}</div>
                  <div className="nist-spec">{t.spec}</div>
                </div>
              )) : (
                <div style={{fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)', padding:'10px 0'}}>
                  <span className="spinner" style={{display:'inline-block', verticalAlign:'middle', marginRight:8}}/>
                  running KATs against the real Python implementation…
                </div>
              )}
              <div className="nist-badge" style={{opacity:0.75}}>
                <div className="check" style={{background:'var(--primary-container)', color:'var(--on-primary-container)'}}>i</div>
                <div className="nist-name" style={{fontSize:12, color:'var(--ink-dim)'}}>Full suite: 62 tests · run via <code>make test</code></div>
                <div className="nist-spec">tests/</div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-title"><span className="num">⑤</span> Security model</div>
            <div style={{display:'flex', flexDirection:'column', gap:8, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-dim)', lineHeight:1.6}}>
              <div><span style={{color:'var(--accent)'}}>•</span> <strong style={{color:'var(--ink)'}}>Encrypt-then-MAC</strong> — MAC over ciphertext, not plaintext. Strongest composition; rejects forgeries cheaply.</div>
              <div><span style={{color:'var(--accent)'}}>•</span> <strong style={{color:'var(--ink)'}}>Authenticated</strong> — single flipped bit anywhere in the blob is detected before any decryption output.</div>
              <div><span style={{color:'var(--accent)'}}>•</span> <strong style={{color:'var(--ink)'}}>Constant-time tag compare</strong> — defeats timing side channels.</div>
              <div><span style={{color:'var(--accent)'}}>•</span> <strong style={{color:'var(--ink)'}}>Fresh nonce per file</strong> — 96 random bits ≪ birthday bound for any reasonable scale.</div>
              <div><span style={{color:'var(--accent)'}}>•</span> <strong style={{color:'var(--ink)'}}>Identical failure mode</strong> — "wrong password" and "tampered file" return the same error. No information leak.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

window.InternalsScreen = InternalsScreen;
