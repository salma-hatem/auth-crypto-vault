// App shell — sidebar nav + screen routing

const { useState: useStateA } = React;

const NAV = [
  { id: 'encrypt',   label: 'Encrypt',     icon: 'lock',   shortcut: '1', title: 'Encrypt → Vault',           crumb: 'acv:// encrypt' },
  { id: 'decrypt',   label: 'Decrypt',     icon: 'unlock', shortcut: '2', title: 'Decrypt → Plaintext',       crumb: 'acv:// decrypt' },
  { id: 'internals', label: 'Internals',   icon: 'cpu',    shortcut: '3', title: 'Crypto pipeline internals', crumb: 'acv:// internals' },
  { id: 'benchmark', label: 'Benchmark',   icon: 'gauge',  shortcut: '4', title: 'Backend benchmark',          crumb: 'acv:// bench' },
  { id: 'tamper',    label: 'Tamper Demo', icon: 'alert',  shortcut: '5', title: 'Tamper detection demo',     crumb: 'acv:// tamper' },
];

function App() {
  const [route, setRoute]     = useStateA('encrypt');
  const [backend, setBackend] = useStateA('v2');
  const [theme, setTheme]     = useStateA(() => {
    try { return localStorage.getItem('acv-theme') || 'dark'; }
    catch (e) { return 'dark'; }
  });

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('acv-theme', theme); } catch (e) {}
  }, [theme]);

  // Keyboard shortcuts 1-5
  React.useEffect(() => {
    function onKey(e) {
      if (e.target.tagName === 'INPUT') return;
      const item = NAV.find(n => n.shortcut === e.key);
      if (item) setRoute(item.id);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const cur = NAV.find(n => n.id === route);

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
        </div>
      </aside>

      <main className="main">
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
