// Benchmark screen — calls /api/benchmark (real V1 vs V2 Python timing)

const { useState: useStateB, useEffect: useEffectB, useRef: useRefB } = React;

function BenchmarkScreen() {
  const [size, setSize] = useStateB(1);
  const [running, setRunning] = useStateB(false);
  const [done, setDone] = useStateB(false);
  const [results, setResults] = useStateB(null);
  const [error, setError] = useStateB(null);
  const [showBars, setShowBars] = useStateB(false); // triggers CSS transition

  async function run() {
    setRunning(true);
    setDone(false);
    setResults(null);
    setError(null);
    setShowBars(false);

    try {
      const resp = await fetch('/api/benchmark', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size_mb: size }),
      });
      const data = await resp.json();

      setResults({
        v1: { time: data.v1.time_ms, throughput: data.v1.throughput_mbs, capped: data.v1.capped, actual_mb: data.v1.size_mb },
        v2: { time: data.v2.time_ms, throughput: data.v2.throughput_mbs, backend: data.v2.backend, actual_mb: data.v2.size_mb },
        speedup: data.speedup,
      });
      setDone(true);
      // small delay so the bars animate from 0
      setTimeout(() => setShowBars(true), 80);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  }

  const v1Tput = results?.v1.throughput || 0;
  const v2Tput = results?.v2.throughput || 0;
  const maxTput = Math.max(v1Tput, v2Tput) * 1.05 || 1;

  return (
    <div className="content">
      <div className="card">
        <div className="card-title">
          <span className="num">BENCH</span> AES-128-CTR throughput · V1 (pure Python) vs V2 (T-tables / C)
        </div>

        <div style={{display:'flex', gap:14, alignItems:'flex-end', marginBottom:18, flexWrap:'wrap'}}>
          <div style={{flex:'0 0 auto'}}>
            <div className="label">V2 data size</div>
            <div style={{display:'flex', gap:6}}>
              {[1, 5, 25].map(s => (
                <button key={s}
                  className={'btn ' + (size === s ? '' : 'ghost')}
                  style={{padding:'8px 14px', fontFamily:'var(--font-mono)', fontSize:12}}
                  onClick={() => setSize(s)} disabled={running}>
                  {s} MB
                </button>
              ))}
            </div>
          </div>
          <div style={{flex:'0 0 auto'}}>
            <div className="label">V1 input</div>
            <div className="mono-pill" style={{padding:'8px 12px'}}>
              64 KB (capped — full size takes minutes)
            </div>
          </div>
          <div style={{flex:1}}/>
          <button className="btn primary lg" onClick={run} disabled={running}>
            {running ? <><span className="spinner"/> Benchmarking…</> : <><Icon name="play" size={13}/> Run benchmark</>}
          </button>
        </div>

        {running && (
          <div style={{marginBottom:18, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)'}}>
            <span className="spinner" style={{display:'inline-block', verticalAlign:'middle', marginRight:8}}/>
            Running V1 on 64 KB, then V2 on {size} MB (3 runs) via real Python…
          </div>
        )}

        {error && (
          <div className="status err" style={{marginBottom:18}}>
            <div className="st-icon">✗</div>
            <div><div className="status-title">Benchmark failed</div><div className="status-body">{error}</div></div>
          </div>
        )}

        {/* Bar chart */}
        <div className="section-h">throughput · MB / s</div>
        <div className="bar-chart">
          <div className="bar-row">
            <div className="bar-label" style={{color:'var(--nonce)'}}>V1 · Python</div>
            <div className="bar-track">
              <div className="bar-fill v1" style={{width: showBars && done ? (v1Tput / maxTput * 100) + '%' : '0%', transition:'width 1s cubic-bezier(0.4,0,0.2,1)'}}>
                {done && v1Tput.toFixed(2) + ' MB/s'}
              </div>
            </div>
          </div>
          <div className="bar-row">
            <div className="bar-label" style={{color:'var(--hmac)'}}>V2 · T-tables</div>
            <div className="bar-track">
              <div className="bar-fill v2" style={{width: showBars && done ? (v2Tput / maxTput * 100) + '%' : '0%', transition:'width 1s cubic-bezier(0.4,0,0.2,1)'}}>
                {done && v2Tput.toFixed(0) + ' MB/s'}
              </div>
              {running && <div className="bar-shimmer"/>}
            </div>
          </div>
        </div>

        {/* Results table */}
        <div style={{marginTop:24}}>
          <div className="section-h">results</div>
          <table className="bench-table">
            <thead>
              <tr>
                <th>Backend</th>
                <th>Data size</th>
                <th>Time (ms)</th>
                <th>Throughput (MB/s)</th>
                <th>Speedup</th>
                <th>Implementation</th>
              </tr>
            </thead>
            <tbody>
              <tr className="row-v1">
                <td style={{color:'var(--nonce)'}}>● V1 Pure Python</td>
                <td>{done ? results.v1.actual_mb.toFixed(3) + ' MB' : '—'}</td>
                <td>{done ? results.v1.time.toFixed(1) : '—'}</td>
                <td>{done ? results.v1.throughput.toFixed(2) : '—'}</td>
                <td>1.00 ×</td>
                <td style={{color:'var(--ink-mute)'}}>aes/ · S-box lookup, pure Python</td>
              </tr>
              <tr className="row-v2">
                <td style={{color:'var(--hmac)'}}>● V2 T-tables / C</td>
                <td>{done ? results.v2.actual_mb.toFixed(2) + ' MB' : '—'}</td>
                <td>{done ? results.v2.time.toFixed(1) : '—'}</td>
                <td>{done ? results.v2.throughput.toFixed(0) : '—'}</td>
                <td style={{color:'var(--hmac)', fontWeight:600}}>
                  {done ? results.speedup.toFixed(0) + ' ×' : '—'}
                </td>
                <td style={{color:'var(--ink-mute)'}}>
                  {done ? `aes_v2/ · 4× T-tables · ${results.v2.backend} backend` : '—'}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Metrics */}
        {done && (
          <div className="grid-3" style={{marginTop:18}}>
            <div className="metric">
              <div className="m-lbl">Speedup factor</div>
              <div className="m-val" style={{color:'var(--hmac)'}}>{results.speedup.toFixed(0)} ×</div>
              <div className="m-sub">V2 vs V1, throughput ratio</div>
            </div>
            <div className="metric">
              <div className="m-lbl">V1 throughput</div>
              <div className="m-val">{results.v1.throughput.toFixed(2)}</div>
              <div className="m-sub">MB/s on 64 KB</div>
            </div>
            <div className="metric">
              <div className="m-lbl">V2 throughput</div>
              <div className="m-val" style={{color:'var(--hmac)'}}>{results.v2.throughput.toFixed(0)}</div>
              <div className="m-sub">MB/s on {size} MB</div>
            </div>
          </div>
        )}

        <div style={{marginTop:18, padding:'12px 14px', background:'var(--bg-2)', borderLeft:'3px solid var(--accent)', borderRadius:8, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-dim)', lineHeight:1.6}}>
          <strong style={{color:'var(--ink)'}}>How it works.</strong> V1 implements AES from scratch in pure Python — each round does SubBytes / ShiftRows / MixColumns as separate ops. V2 collapses one round into <em>four</em> table lookups + XORs (the classic 4×T-table technique by Daemen &amp; Rijmen). The C extension adds: unrolled rounds and SIMD-aligned tables. V1 is capped at 64 KB in this UI; run <code>make bench</code> for the full 5 MB comparison.
        </div>
      </div>
    </div>
  );
}

window.BenchmarkScreen = BenchmarkScreen;
