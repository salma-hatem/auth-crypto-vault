// App shell — sidebar nav + screen routing

const { useState: useStateA, useEffect: useEffectA } = React;

const NAV = [
  { id: 'encrypt',   label: 'Encrypt',     icon: 'lock',   shortcut: '1', title: 'Encrypt → Vault',           crumb: 'acv:// encrypt' },
  { id: 'decrypt',   label: 'Decrypt',     icon: 'unlock', shortcut: '2', title: 'Decrypt → Plaintext',       crumb: 'acv:// decrypt' },
  { id: 'internals', label: 'Internals',   icon: 'cpu',    shortcut: '3', title: 'Crypto pipeline internals', crumb: 'acv:// internals' },
  { id: 'benchmark', label: 'Benchmark',   icon: 'gauge',  shortcut: '4', title: 'Backend benchmark',          crumb: 'acv:// bench' },
  { id: 'tamper',    label: 'Tamper Demo', icon: 'alert',  shortcut: '5', title: 'Tamper detection demo',     crumb: 'acv:// tamper' },
];

function App() {
  const [route, setRoute]       = useStateA('encrypt');
  const [backend, setBackend]   = useStateA('v2');
  const [serverOk, setServerOk] = useStateA(null); // null=checking, true=ok, false=down
  const [theme, setTheme]       = useStateA(() => {
    try { return localStorage.getItem('acv-theme') || 'dark'; }
    catch (e) { return 'dark'; }
  });

  useEffectA(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('acv-theme', theme); } catch (e) {}
  }, [theme]);

  // Ping the server every 4 s; update the status dot accordingly
  useEffectA(() => {
    function ping() {
      fetch('/api/ping')
        .then(r => r.ok ? setServerOk(true) : setServerOk(false))
        .catch(() => setServerOk(false));
    }
    ping();
    const t = setInterval(ping, 4000);
    return () => clearInterval(t);
  }, []);

  // Keyboard shortcuts 1-5
  useEffectA(() => {
    function onKey(e) {
      if (e.target.tagName === 'INPUT') return;
      const item = NAV.find(n => n.shortcut === e.key);
      if (item) setRoute(item.id);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const cur = NAV.find(n => n.id === route);

  const serverColor = serverOk === null ? 'var(--ink-mute)' : serverOk ? 'var(--hmac)' : 'var(--warn)';
  const serverLabel = serverOk === null ? 'connecting…' : serverOk ? 'server online' : 'server offline';

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">A</div>
          <div className="brand-text">
            <div className="brand-name">ACV</div>
            <div className="brand-sub">Authenticated Vault</div>
          </div>
        </div>

        {NAV.map(item => (
          <div
            key={item.id}
            className={'nav-item ' + (route === item.id ? 'active' : '')}
            onClick={() => setRoute(item.id)}>
            <span className="nav-icon">
              <Icon name={item.icon} size={15}/>
            </span>
            {item.label}
            <span className="nav-shortcut">{item.shortcut}</span>
          </div>
        ))}

        <div className="sidebar-foot">
          <div className="zero-badge">
            <span className="dot"/>
            <span style={{color:'var(--ink-dim)'}}>Zero external crypto libs</span>
          </div>
          <div>AES · SHA-512 · HMAC<br/>built from scratch in py / c</div>
          <div style={{marginTop:8, opacity:0.6}}>CIE 582 · spring 2026</div>
          {/* Server status indicator */}
          <div style={{marginTop:10, display:'flex', alignItems:'center', gap:6}}>
            <span style={{width:7, height:7, borderRadius:'50%', background: serverColor, display:'inline-block',
              boxShadow: serverOk ? '0 0 6px var(--hmac)' : serverOk === false ? '0 0 6px var(--warn)' : 'none'}}/>
            <span style={{color: serverColor, fontSize:10}}>{serverLabel}</span>
          </div>
          {serverOk === false && (
            <div style={{marginTop:6, fontSize:10, color:'var(--warn)', lineHeight:1.5, fontFamily:'var(--font-mono)'}}>
              run: python gui/server.py
            </div>
          )}
        </div>
      </aside>

      <main className="main">
        {/* Offline banner */}
        {serverOk === false && (
          <div style={{background:'var(--warn-container)', color:'var(--warn-on-container)',
            padding:'10px 36px', fontSize:12, fontFamily:'var(--font-mono)',
            display:'flex', alignItems:'center', gap:10, flexShrink:0}}>
            <Icon name="alert" size={14}/>
            Server offline — encrypt/decrypt will fail.
            &nbsp;Start it with: <strong>python gui/server.py</strong>
          </div>
        )}

        <div className="topbar">
          <span className="crumb">{cur.crumb}</span>
          <h1>{cur.title}</h1>
          <div className="spacer"/>
          <button
            className="theme-toggle"
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            aria-label="toggle theme">
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={16}/>
          </button>
          <span style={{fontFamily:'var(--font-mono)', fontSize:11, color:'var(--ink-mute)'}}>Backend</span>
          <BackendSwitch value={backend} onChange={setBackend}/>
        </div>

        {route === 'encrypt'   && <EncryptScreen backend={backend}/>}
        {route === 'decrypt'   && <DecryptScreen backend={backend}/>}
        {route === 'internals' && <InternalsScreen backend={backend}/>}
        {route === 'benchmark' && <BenchmarkScreen/>}
        {route === 'tamper'    && <TamperScreen/>}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
