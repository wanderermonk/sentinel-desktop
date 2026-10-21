const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  config: () => ipcRenderer.invoke('config'),
  notify: (title, body, view) => ipcRenderer.invoke('notify', { title, body, view }),
  elevate: () => ipcRenderer.invoke('elevate'),
  openFile: filters => ipcRenderer.invoke('open-file', filters),
  saveFile: (name, text) => ipcRenderer.invoke('save-file', { name, text }),
  showItem: p => ipcRenderer.invoke('show-item', p),
  openUrl: u => ipcRenderer.invoke('open-url', u),
  onNavigate: cb => ipcRenderer.on('navigate', (_e, v) => cb(v)),
  onBackendDown: cb => ipcRenderer.on('backend-down', () => cb()),
  onBackendRestarted: cb => ipcRenderer.on('backend-restarted', (_e, port) => cb(port)),
  onResumed: cb => ipcRenderer.on('resumed', (_e, why) => cb(why)),
  autostart: on => ipcRenderer.invoke('autostart', on),
});
