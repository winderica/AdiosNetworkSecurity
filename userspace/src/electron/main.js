const isDev = process.env.NODE_ENV === 'development';

const { app, BrowserWindow } = require('electron')

app.whenReady().then(async () => {
    const mainWindow = new BrowserWindow({
        width: 1280,
        height: 720,
        webPreferences: {
            nodeIntegration: true,
            nodeIntegrationInWorker: true,
        },
    });

    if (isDev) {
        mainWindow.loadURL('http://localhost:3000');
    } else {
        mainWindow.loadFile('./build/index.html');
    }

    isDev && mainWindow.webContents.openDevTools();
});

app.on('window-all-closed', () => {
    app.quit();
});
