// Sentinel - Electron main process.
// Spawns the bundled Python scanning engine on 127.0.0.1 with a random token,
// hosts the dark UI, raises native notifications and keeps monitoring from the tray.
const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, dialog, nativeImage, shell, powerMonitor, powerSaveBlocker } = require('electron');
const { spawn, execFile, execFileSync } = require('child_process');
const os = require('os');
const path = require('path');
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');

const isMac = process.platform === 'darwin';
const isWin = process.platform === 'win32';
let win = null;
let tray = null;
let backend = null;
let quitting = false;
const cfg = { port: null, token: crypto.randomBytes(24).toString('hex'), elevated: false };

const PROJECT_ROOT = path.join(__dirname, '..');

// Same location the Python engine uses (store.data_dir), shared by normal and elevated engines.
function dataDir() {
  const d = isWin ? path.join(process.env.APPDATA || app.getPath('home'), 'Sentinel')
    : isMac ? path.join(app.getPath('home'), 'Library', 'Application Support', 'Sentinel')
    : path.join(app.getPath('home'), '.sentinel');
  fs.mkdirSync(d, { recursive: true });
  return d;
}

// DeskMonitor link: publish the engine's port + token in an owner-only file so the
// desktop widget can read /api/summary. Removed again when Sentinel quits.
function publishEngine() {
  const f = path.join(dataDir(), 'engine.json');
  try {
    if (!cfg.port || quitting) { fs.rmSync(f, { force: true }); return; }
    fs.writeFileSync(f, JSON.stringify({ port: cfg.port, token: cfg.token, pid: process.pid, elevated: cfg.elevated }), { mode: 0o600 });
    if (!isWin) fs.chmodSync(f, 0o600);
  } catch (_) {}
}

// Absolute path to an executable: elevated shells run from '/' with root's PATH,
// so relative paths (.venv/bin/python) and bare names (python3) would resolve differently.
function absoluteExe(cmd) {
  if (path.isAbsolute(cmd)) return cmd;
  if (cmd.includes('/') || cmd.includes('\\')) {
    const fromCwd = path.resolve(process.cwd(), cmd);
    return fs.existsSync(fromCwd) ? fromCwd : path.resolve(PROJECT_ROOT, cmd);
  }
  try {
    const { execFileSync } = require('child_process');
    const out = execFileSync(isWin ? 'where' : '/usr/bin/which', [cmd], { encoding: 'utf8' }).split(/\r?\n/)[0].trim();
    if (out) return out;
  } catch (_) { /* fall through */ }
  return cmd;
}

function backendCommand() {
  const exe = isWin ? 'sentinel-backend.exe' : 'sentinel-backend';
  const packaged = path.join(process.resourcesPath || '', 'backend', exe);
  if (app.isPackaged && fs.existsSync(packaged)) return { cmd: packaged, args: [] };
  // development: run the Python source directly (prefer the project's .venv if present)
  const venvPy = path.join(PROJECT_ROOT, '.venv', isWin ? 'Scripts/python.exe' : 'bin/python');
  const py = process.env.SENTINEL_PYTHON || (fs.existsSync(venvPy) ? venvPy : (isWin ? 'python' : 'python3'));
  return { cmd: absoluteExe(py), args: [path.join(PROJECT_ROOT, 'backend', 'server.py')] };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
    s.on('error', reject);
  });
}

async function waitHealthy(port, ms = 20000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/health`, { headers: { 'X-Sentinel-Token': cfg.token } });
      if (r.ok) return true;
    } catch (_) { /* not up yet */ }
    await new Promise(r => setTimeout(r, 300));
  }
  return false;
}

// Engine output goes to <data>/engine.log so a failed start can say *why* it failed.
function engineLog() { return path.join(dataDir(), 'engine.log'); }
function logTail(n = 12) {
  try { return fs.readFileSync(engineLog(), 'utf8').trim().split('\n').slice(-n).join('\n'); } catch (_) { return ''; }
}

async function startBackend() {
  const { cmd, args } = backendCommand();
  if (!fs.existsSync(cmd) && path.isAbsolute(cmd)) throw new Error(`Scanning engine is missing: ${cmd}`);
  const port = await freePort();
  try { fs.renameSync(engineLog(), engineLog() + '.1'); } catch (_) {}
  const log = fs.openSync(engineLog(), 'a');
  fs.writeSync(log, `[${new Date().toISOString()}] starting ${cmd} ${args.join(' ')} --port ${port}\n`);
  backend = spawn(cmd, [...args, '--port', String(port), '--token', cfg.token, '--parent-pid', String(process.pid)], {
    windowsHide: true, stdio: ['ignore', log, log],
    env: { ...process.env, PYTHONUNBUFFERED: '1', SENTINEL_DATA: dataDir() },
  });
  fs.closeSync(log);
  const me = backend;
  let exited = null;
  backend.on('error', e => { exited = `could not be launched (${e.code || e.message})`; });
  backend.on('exit', (code, signal) => {
    exited = signal ? `was killed by ${signal}${signal === 'SIGKILL' && isMac ? ' (macOS usually does this to a binary with an invalid code signature)' : ''}`
      : `exited with code ${code}`;
    console.log('[backend]', exited);
    if (!cfg.port || quitting || cfg.elevated || backend !== me) return;   // still starting, or intentional
    restartBackend('engine ' + exited);
  });
  // first launch can be slow: the frozen engine unpacks itself and macOS scans it
  const until = Date.now() + 90000;
  let healthy = false;
  while (!healthy && !exited && Date.now() < until) {
    healthy = await waitHealthy(port, 1000);
  }
  if (!healthy) {
    try { me.kill(); } catch (_) {}
    const why = exited ? `The engine ${exited}.` : 'The engine did not respond within 90 seconds.';
    const tail = logTail();
    throw new Error(`Scanning engine failed to start.\n${why}\n\n${tail ? 'Last output:\n' + tail + '\n\n' : ''}Full log: ${engineLog()}`);
  }
  cfg.port = port;
  cfg.elevated = false;
  publishEngine();
}

// Bring the engine back after a crash or a failed wake-up, then point the UI at the new port.
let restarting = false;
async function restartBackend(reason) {
  if (restarting || quitting) return;
  restarting = true;
  console.log('[backend] restarting:', reason);
  for (let attempt = 1; attempt <= 5 && !quitting; attempt++) {
    try {
      try { backend && backend.kill(); } catch (_) {}
      backend = null; cfg.port = null;
      await new Promise(r => setTimeout(r, 1500 * attempt));
      await startBackend();
      if (win) win.webContents.send('backend-restarted', cfg.port);
      break;
    } catch (e) {
      console.error('[backend] restart failed', e.message);
      if (attempt === 5 && win) win.webContents.send('backend-down');
    }
  }
  restarting = false;
}

async function backendAlive() {
  if (!cfg.port) return false;
  try {
    const r = await fetch(`http://127.0.0.1:${cfg.port}/api/health`, { headers: { 'X-Sentinel-Token': cfg.token }, signal: AbortSignal.timeout(4000) });
    return r.ok;
  } catch (_) { return false; }
}

// ------------------------------------------------------------------ start at login (always-on)
// macOS: a per-user LaunchAgent starts Sentinel hidden at every login and relaunches it if it crashes
// (KeepAlive/SuccessfulExit=false). Choosing "Quit" exits cleanly, so launchd leaves it stopped until next login.
// Windows: the standard login item. Linux: ~/.config/autostart desktop entry.
const AGENT_LABEL = 'com.fighter.sentinel';
const agentPlist = () => path.join(os.homedir(), 'Library', 'LaunchAgents', `${AGENT_LABEL}.plist`);
function launchArgs() {
  return app.isPackaged ? [process.execPath, '--hidden'] : [process.execPath, app.getAppPath(), '--hidden'];
}
const autoStart = {
  get() {
    if (isMac) return fs.existsSync(agentPlist());
    if (isWin) return app.getLoginItemSettings().openAtLogin;
    return fs.existsSync(path.join(os.homedir(), '.config', 'autostart', 'sentinel.desktop'));
  },
  set(on) {
    if (isMac) {
      const uid = process.getuid();
      try { execFileSync('/bin/launchctl', ['bootout', `gui/${uid}/${AGENT_LABEL}`], { stdio: 'ignore' }); } catch (_) {}
      if (!on) { fs.rmSync(agentPlist(), { force: true }); return; }
      const xml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${AGENT_LABEL}</string>
  <key>ProgramArguments</key><array>${launchArgs().map(a => `<string>${xml(a)}</string>`).join('')}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>StandardErrorPath</key><string>${xml(path.join(dataDir(), 'sentinel-agent.log'))}</string>
</dict></plist>
`;
      fs.mkdirSync(path.dirname(agentPlist()), { recursive: true });
      fs.writeFileSync(agentPlist(), plist);
      // register now; the copy launchd starts sees we're already running (single-instance lock) and exits cleanly
      try { execFileSync('/bin/launchctl', ['bootstrap', `gui/${uid}`, agentPlist()], { stdio: 'ignore' }); } catch (_) {}
      return;
    }
    if (isWin) { app.setLoginItemSettings({ openAtLogin: on, args: ['--hidden'] }); return; }
    const f = path.join(os.homedir(), '.config', 'autostart', 'sentinel.desktop');
    if (!on) { fs.rmSync(f, { force: true }); return; }
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, `[Desktop Entry]\nType=Application\nName=Sentinel\nExec=${launchArgs().map(a => `"${a}"`).join(' ')}\nX-GNOME-Autostart-enabled=true\n`);
  },
};

// Turn always-on monitoring on the first time the installed app runs (the user can switch it off in the tray).
function firstRunAutoStart() {
  const flag = path.join(dataDir(), 'ui.json');
  let st = {};
  try { st = JSON.parse(fs.readFileSync(flag, 'utf8')); } catch (_) {}
  if (!st.autostartConfigured && app.isPackaged) {
    try { autoStart.set(true); } catch (e) { console.error('autostart', e); }
    st.autostartConfigured = true;
    fs.writeFileSync(flag, JSON.stringify(st));
  } else if (st.autostartConfigured && isMac && autoStart.get()) {
    // app was moved/updated: keep the LaunchAgent pointing at the current binary
    try { if (!fs.readFileSync(agentPlist(), 'utf8').includes(process.execPath)) autoStart.set(true); } catch (_) {}
  }
}

// ------------------------------------------------------------------ sleep / wake
function watchPower() {
  // stop macOS App Nap from throttling the hidden app and its engine (does NOT keep the Mac awake)
  powerSaveBlocker.start('prevent-app-suspension');
  const recheck = async why => {
    if (quitting) return;
    await new Promise(r => setTimeout(r, 3000));          // let the network come back first
    if (await backendAlive()) {
      fetch(`http://127.0.0.1:${cfg.port}/api/egress/resume`, { method: 'POST', headers: { 'X-Sentinel-Token': cfg.token } }).catch(() => {});
      if (win) win.webContents.send('resumed', why);
    } else if (!cfg.elevated) {
      restartBackend(`not responding after ${why}`);
    } else if (win) {
      win.webContents.send('backend-down');
    }
  };
  powerMonitor.on('resume', () => recheck('wake from sleep'));
  powerMonitor.on('unlock-screen', () => recheck('screen unlock'));
  // belt and braces: a light health check every minute catches anything the events miss
  setInterval(async () => { if (!quitting && !restarting && !cfg.elevated && !(await backendAlive())) restartBackend('health check failed'); }, 60000);
}

// macOS privacy protection (TCC) stops root processes started from a password prompt reading
// ~/Documents, ~/Desktop and ~/Downloads. In development the engine and its .venv live in the project
// folder, so copy the engine + psutil to Application Support and run the base Python interpreter.
// (The installed app keeps its engine inside Sentinel.app, which is not protected, so it is used as-is.)
function adminEngineCommand() {
  const base = backendCommand();
  if (app.isPackaged && path.isAbsolute(base.cmd) && base.cmd.startsWith(process.resourcesPath)) return base;
  const { execFileSync } = require('child_process');
  const info = JSON.parse(execFileSync(base.cmd, ['-c',
    'import sys, os, json, psutil; print(json.dumps({"py": os.path.realpath(getattr(sys, "_base_executable", sys.executable)), "psutil": os.path.dirname(psutil.__file__)}))'],
    { encoding: 'utf8' }).trim().split('\n').pop());
  const dest = path.join(dataDir(), 'admin-engine');
  fs.rmSync(dest, { recursive: true, force: true });
  fs.cpSync(path.join(PROJECT_ROOT, 'backend'), path.join(dest, 'backend'), {
    recursive: true, filter: src => !src.includes('__pycache__') && !src.includes(path.sep + 'tests'),
  });
  fs.cpSync(info.psutil, path.join(dest, 'lib', 'psutil'), { recursive: true });
  return { cmd: info.py, args: ['-s', path.join(dest, 'backend', 'server.py')], pyPath: path.join(dest, 'lib') };
}

// macOS/Linux: restart the engine with administrator rights (system-wide socket visibility).
// Windows builds request admin via the app manifest instead.
async function elevateBackend() {
  if (isWin) return { ok: false, error: 'On Windows, right-click Sentinel and choose "Run as administrator".' };
  let cmd, args, pyPath = '';
  try { ({ cmd, args, pyPath } = adminEngineCommand()); }
  catch (e) { return { ok: false, error: 'Could not prepare admin engine: ' + (e.message || e) }; }
  const port = await freePort();
  const q = s => `'${String(s).replace(/'/g, `'\\''`)}'`;
  const log = path.join(dataDir(), 'engine-admin.log');
  // No nohup: macOS 'do shell script' has no console, so nohup refuses to run. There is no tty to
  // send SIGHUP either; detaching stdin/stdout is enough for the engine to outlive the prompt.
  const line = `SENTINEL_DATA=${q(dataDir())} PYTHONUNBUFFERED=1 ${pyPath ? 'PYTHONPATH=' + q(pyPath) + ' ' : ''}` +
    [cmd, ...args, '--port', port, '--token', cfg.token, '--parent-pid', process.pid].map(q).join(' ') +
    ` </dev/null >${q(log)} 2>&1 &`;
  return new Promise(resolve => {
    const runner = isMac
      ? ['osascript', ['-e', `do shell script "${line.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" with administrator privileges`]]
      : ['pkexec', ['/bin/sh', '-c', line]];
    execFile(runner[0], runner[1], async (err, _out, stderr) => {
      if (err) {
        const cancelled = /-128|cancel/i.test(String(stderr || err.message));
        return resolve({ ok: false, error: cancelled ? 'Administrator permission was not granted.' : `Could not start admin engine: ${String(stderr || err.message).trim()}` });
      }
      if (!(await waitHealthy(port))) {
        let tail = '';
        try { tail = fs.readFileSync(log, 'utf8').trim().split('\n').slice(-3).join('\n'); } catch (_) {}
        return resolve({ ok: false, error: `Admin engine did not start. ${tail || 'See ' + log}` });
      }
      const old = backend; cfg.elevated = true; cfg.port = port; backend = null;
      publishEngine();
      try { old && old.kill(); } catch (_) {}
      resolve({ ok: true, port });
    });
  });
}

function stopBackend() {
  quitting = true;
  publishEngine();   // quitting -> removes engine.json
  try { backend && backend.kill(); } catch (_) {}
  if (cfg.elevated && cfg.port) {
    // the elevated engine runs as root and cannot be killed by us: ask it to exit (it also watches our PID)
    fetch(`http://127.0.0.1:${cfg.port}/api/shutdown`, { method: 'POST', headers: { 'X-Sentinel-Token': cfg.token } }).catch(() => {});
  }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1480, height: 940, minWidth: 1100, minHeight: 700,
    backgroundColor: '#0d0f12',
    title: 'Sentinel',
    // launched at login -> stay in the tray; the renderer still runs and raises alerts
    show: !process.argv.includes('--hidden'),
    titleBarStyle: isMac ? 'hiddenInset' : 'default',
    autoHideMenuBar: true,
    icon: path.join(__dirname, '..', 'build', 'icon.png'),
    webPreferences: {
      backgroundThrottling: false,   // keep alert polling + notifications running while hidden in the tray
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  // no external navigation: the app is fully offline
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.on('close', e => {
    if (!quitting && tray) { e.preventDefault(); win.hide(); }
  });
}

function createTray() {
  try {
    const img = isMac
      ? nativeImage.createFromPath(path.join(__dirname, '..', 'build', 'trayTemplate.png'))   // auto-tinted menu-bar template
      : nativeImage.createFromPath(path.join(__dirname, '..', 'build', 'icon.png')).resize({ width: 16, height: 16 });
    tray = new Tray(img);
    tray.setToolTip('Sentinel - monitoring connections and data leaving this computer');
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Open Sentinel', click: () => { win.show(); win.focus(); } },
      { label: 'Data leaving this computer', click: () => { win.show(); win.focus(); win.webContents.send('navigate', 'egress'); } },
      { type: 'separator' },
      // Always-on: start hidden in the tray at login (and relaunch after a crash) so monitoring never stops.
      { label: 'Start automatically at login', type: 'checkbox', checked: autoStart.get(),
        click: item => { try { autoStart.set(item.checked); } catch (e) { dialog.showErrorBox('Sentinel', String(e.message || e)); } } },
      { type: 'separator' },
      { label: 'Quit (stop monitoring)', click: () => { quitting = true; app.quit(); } },
    ]));
    tray.on('click', () => { win.show(); win.focus(); });
  } catch (e) { tray = null; }
}

ipcMain.handle('config', () => ({ port: cfg.port, token: cfg.token, platform: process.platform, elevated: cfg.elevated, version: app.getVersion() }));
ipcMain.handle('notify', (_e, { title, body, view }) => {
  if (Notification.isSupported()) {
    const n = new Notification({ title, body, silent: false });
    n.on('click', () => { win.show(); win.focus(); win.webContents.send('navigate', view === 'egress' ? 'egress' : 'network'); });
    n.show();
  }
});
ipcMain.handle('elevate', () => elevateBackend());
ipcMain.handle('autostart', (_e, on) => { if (typeof on === 'boolean') autoStart.set(on); return autoStart.get(); });
ipcMain.handle('open-file', async (_e, filters) => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile'], filters: filters || [{ name: 'Text/JSON', extensions: ['txt', 'json', 'csv', 'list', 'hosts'] }] });
  if (r.canceled || !r.filePaths[0]) return null;
  const p = r.filePaths[0];
  const stat = fs.statSync(p);
  if (stat.size > 20 * 1024 * 1024) throw new Error('File too large (max 20 MB)');
  return { name: path.basename(p), text: fs.readFileSync(p, 'utf8') };
});
ipcMain.handle('save-file', async (_e, { name, text }) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: name });
  if (r.canceled || !r.filePath) return false;
  fs.writeFileSync(r.filePath, text, 'utf8');
  return true;
});
// Only OS settings panes - Sentinel never opens web pages.
ipcMain.handle('open-url', (_e, u) => {
  if (/^(x-apple\.systempreferences:|ms-settings:)/.test(String(u))) return shell.openExternal(u);
});
ipcMain.handle('show-item', (_e, p) => { if (p && fs.existsSync(p)) shell.showItemInFolder(p); });

const single = app.requestSingleInstanceLock();
if (!single) app.quit();
app.on('second-instance', () => { if (win) { win.show(); win.focus(); } });

app.whenReady().then(async () => {
  try {
    await startBackend();
  } catch (e) {
    if (process.argv.includes('--hidden')) { console.error(e); app.exit(1); return; }  // at login: let launchd retry
    dialog.showErrorBox('Sentinel', String(e.message || e));
    app.quit();
    return;
  }
  firstRunAutoStart();
  createWindow();
  createTray();
  watchPower();
  app.on('activate', () => { if (win) win.show(); });
});

app.on('before-quit', () => { quitting = true; stopBackend(); });
app.on('window-all-closed', () => { if (!tray) app.quit(); });
