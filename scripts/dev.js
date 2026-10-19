/**
 * Concurrent development launcher for EVM Honeypot Detector.
 * Runs both the Express backend (port 5000) and Vite frontend (port 3000) concurrently
 * without requiring third-party dependencies like 'concurrently'.
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const net = require('net');

const rootDir = path.resolve(__dirname, '..');
const clientDir = path.resolve(rootDir, 'client');
const isWin = process.platform === 'win32';

console.log('\x1b[36m%s\x1b[0m', '=======================================================');
console.log('\x1b[36m%s\x1b[0m', '  Starting EVM Honeypot Detector Full-Stack App        ');
console.log('\x1b[36m%s\x1b[0m', '  - Backend:  http://localhost:5000                    ');
console.log('\x1b[36m%s\x1b[0m', '  - Frontend: http://localhost:3000                    ');
console.log('\x1b[36m%s\x1b[0m', '=======================================================\n');

/**
 * Ensures any lingering process on a given port is terminated prior to launch.
 */
function freePort(port) {
  try {
    if (isWin) {
      const output = execSync('netstat -ano -p tcp', {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore']
      });
      const lines = output.split('\n');
      const pids = new Set();
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.includes(`:${port}`)) continue;
        const parts = line.split(/\s+/);
        if (parts.length >= 5 && parts[1].endsWith(`:${port}`) && parts[3] === 'LISTENING') {
          const pid = parts[4];
          if (pid && pid !== '0' && pid !== String(process.pid)) {
            pids.add(pid);
          }
        }
      }
      for (const pid of pids) {
        console.log(`\x1b[33m[DEV]\x1b[0m Clearing stale process (PID ${pid}) on port ${port}...`);
        try {
          execSync(`taskkill /F /T /PID ${pid}`, { stdio: 'ignore' });
        } catch (_) {}
      }
    } else {
      try {
        const pid = execSync(`lsof -ti:${port}`, {
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
        if (pid) {
          console.log(`\x1b[33m[DEV]\x1b[0m Clearing stale process (PID ${pid}) on port ${port}...`);
          execSync(`kill -9 ${pid}`, { stdio: 'ignore' });
        }
      } catch (_) {}
    }
  } catch (_) {
    // Port is free or lookup command was empty
  }
}

// Pre-flight port cleanup
freePort(5000);
freePort(3000);

function prefixStream(stream, prefix, colorCode) {
  let buffer = '';
  stream.on('data', (data) => {
    buffer += data.toString();
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep last incomplete line in buffer
    for (const line of lines) {
      if (line.trim().length > 0) {
        console.log(`\x1b[${colorCode}m${prefix}\x1b[0m ${line}`);
      }
    }
  });
}

/**
 * Polls a TCP port until a connection succeeds or timeout is reached.
 */
function waitForPort(port, host = '127.0.0.1', timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const tryConnect = () => {
      const socket = new net.Socket();
      socket.setTimeout(800);

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      const handleFail = () => {
        socket.destroy();
        if (Date.now() - startTime >= timeoutMs) {
          reject(new Error(`Timed out waiting for port ${port} on ${host} after ${timeoutMs}ms`));
        } else {
          setTimeout(tryConnect, 150);
        }
      };

      socket.on('error', handleFail);
      socket.on('timeout', handleFail);

      socket.connect(port, host);
    };

    tryConnect();
  });
}

let clientProcess = null;
let isShuttingDown = false;

// 1. Launch Express backend server
const serverProcess = spawn('node', ['server/server.js'], {
  cwd: rootDir,
  env: { ...process.env, PORT: process.env.PORT || '5000' },
  stdio: ['inherit', 'pipe', 'pipe']
});

prefixStream(serverProcess.stdout, '[SERVER]', '35'); // Magenta
prefixStream(serverProcess.stderr, '[SERVER:ERR]', '31'); // Red

// 2. Launch Vite frontend client AFTER Express is ready
async function startClient() {
  console.log('\x1b[36m[DEV]\x1b[0m Waiting for Express backend on http://127.0.0.1:5000 to be ready...');
  try {
    await waitForPort(5000, '127.0.0.1', 25000);
    console.log('\x1b[32m[DEV]\x1b[0m Express backend is active and listening! Launching Vite frontend...\n');
  } catch (err) {
    console.warn(`\x1b[33m[DEV]\x1b[0m Port 5000 probe warning: ${err.message}. Starting Vite frontend anyway...`);
  }

  if (isShuttingDown) return;

  const viteBin = path.resolve(clientDir, 'node_modules/vite/bin/vite.js');
  if (fs.existsSync(viteBin)) {
    clientProcess = spawn('node', [viteBin], {
      cwd: clientDir,
      env: process.env,
      stdio: ['inherit', 'pipe', 'pipe']
    });
  } else {
    // Fallback to npm run dev with shell: true for Windows batch compatibility
    clientProcess = spawn('npm', ['run', 'dev'], {
      cwd: clientDir,
      env: process.env,
      shell: true,
      stdio: ['inherit', 'pipe', 'pipe']
    });
  }

  prefixStream(clientProcess.stdout, '[CLIENT]', '34'); // Blue
  prefixStream(clientProcess.stderr, '[CLIENT:ERR]', '33'); // Yellow

  clientProcess.on('close', (code) => {
    if (code !== 0 && code !== null && !isShuttingDown) {
      console.error(`\x1b[31m[CLIENT exited with code ${code}]\x1b[0m`);
      shutdown();
    }
  });
}

startClient();

function shutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log('\n\x1b[33m%s\x1b[0m', 'Shutting down backend and frontend processes...');

  if (serverProcess && serverProcess.pid) {
    try {
      if (isWin) {
        execSync(`taskkill /pid ${serverProcess.pid} /f /t`, { stdio: 'ignore' });
      } else {
        process.kill(-serverProcess.pid, 'SIGINT');
      }
    } catch (_) {}
  }

  if (clientProcess && clientProcess.pid) {
    try {
      if (isWin) {
        execSync(`taskkill /pid ${clientProcess.pid} /f /t`, { stdio: 'ignore' });
      } else {
        process.kill(-clientProcess.pid, 'SIGINT');
      }
    } catch (_) {}
  }

  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('exit', shutdown);

serverProcess.on('close', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`\x1b[31m[SERVER exited with code ${code}]\x1b[0m`);
    shutdown();
  }
});

