const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const sqlite3 = require("sqlite3");

// Electron main process — desktop notes app
// Risks: nodeIntegration enabled, no auto-update, no crash reporting, unvalidated IPC

let db;
let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      nodeIntegration: true,      // SECURITY RISK: renderer has full Node.js access
      contextIsolation: false,     // SECURITY RISK: no context bridge
    },
  });

  mainWindow.loadFile(path.join(__dirname, "index.html"));
}

app.whenReady().then(() => {
  db = new sqlite3.Database(path.join(app.getPath("userData"), "notes.db"));

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  createWindow();
});

// IPC handlers — no input validation, no channel whitelist
// Any renderer code (including injected scripts) can call these
ipcMain.on("note:create", (event, data) => {
  // No validation on data — could contain malicious SQL
  db.run(`INSERT INTO notes (title, content) VALUES ('${data.title}', '${data.content}')`);
});

ipcMain.on("note:delete", (event, id) => {
  db.run(`DELETE FROM notes WHERE id = ${id}`);
});

ipcMain.on("note:list", (event) => {
  db.all("SELECT * FROM notes", (err, rows) => {
    event.reply("note:list:response", rows);
  });
});

// No auto-update mechanism — users must manually download new versions
// No crash reporting — silent failures in production
// No error handling on DB operations
