const { app, BrowserWindow } = require('electron')

const isDev = process.env.NODE_ENV === 'development';

app.whenReady().then(() => {
    const mainWindow = new BrowserWindow({
        width: 1280,
        height: 720,
        webPreferences: {
            nodeIntegration: true,
            nodeIntegrationInWorker: true,
        },
    });

    isDev ? mainWindow.loadURL('http://localhost:3000') : mainWindow.loadFile('./build/index.html');

    isDev && mainWindow.webContents.openDevTools();
});

app.on('window-all-closed', () => {
    app.quit();
});
