package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/proxy"
)

type UserData struct {
	Name string
	Key  []byte
}

// Routing config (из config.json)
type RouteRule struct {
	Type     string `json:"type"`      // "exact", "suffix", "regex", "list"
	Pattern  string `json:"pattern"`   // домен/суффикс/регэксп (для list не используется)
	ListFile string `json:"list_file"` // путь к файлу списка (для type="list")
	Upstream string `json:"upstream"`  // например "socks5://127.0.0.1:1081"
}

type RoutingBlock struct {
	Rules []RouteRule `json:"rules"`
}

type compiledRule struct {
	typ      string
	pattern  string
	re       *regexp.Regexp
	upstream string
	// Для списков: храним домены в map для быстрого поиска
	listDomains  map[string]bool // домен -> true (точные совпадения)
	listSuffixes []string        // список суффиксов (домены, начинающиеся с точки)
}

// cryptoCache кэширует cipher объекты для переиспользования
type cryptoCache struct {
	block cipher.Block
	gcm   cipher.AEAD
}

var (
	authDB          = make(map[string]UserData) // hash -> UserData
	authMu          sync.RWMutex
	staticIndexPath string
	routingRules    []compiledRule
	routingMu       sync.RWMutex
	logFile         *os.File
	logMu           sync.Mutex

	// Кэш cipher объектов по ключу (hex string)
	cryptoCacheMap sync.Map // string -> *cryptoCache

	// Пул буферов для nonce
	noncePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 12)
		},
	}

	// Флаги командной строки
	listen     = flag.String("listen", ":8080", "Адрес для прослушивания HTTP")
	configFile = flag.String("config", "users.json", "Путь к файлу конфигурации пользователей")

	// Параметры производительности (баланс скорости и совместимости с HTTPS)
	maxQueueSize = flag.Int("max-queue", 1500, "Максимальный размер очереди чанков")
	pollTimeout  = flag.Int("poll-timeout", 8, "Timeout для poll запросов в секундах (рекомендуется 5-8 для CDN)")
	pollInterval = flag.Int("poll-interval", 10, "Интервал проверки очереди в микросекундах")
	chunkSize    = flag.Int("chunk-size", 8192, "Размер буфера чтения в байтах (8192 = 8KB рекомендуется для CDN)")
	readTimeout  = flag.Int("read-timeout", 150, "Timeout чтения из remote в секундах")
	dialTimeout  = flag.Int("dial-timeout", 8, "Timeout подключения к remote в секундах")
	verbose      = flag.Bool("verbose", false, "Включить подробное логирование")
)

// logError логирует ошибки в файл и консоль
func logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logMu.Lock()
	if logFile != nil {
		logFile.WriteString(msg)
		logFile.Sync()
	}
	logMu.Unlock()
	fmt.Print(msg)
	log.Print(msg)
}

// logf условное логирование (только если verbose=true), НЕ пишет в файл
func logf(format string, args ...interface{}) {
	if *verbose {
		msg := fmt.Sprintf(format, args...)
		fmt.Print(msg)
	}
}

// logAlways всегда логирует в консоль, НЕ пишет в файл
func logAlways(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
	log.Print(msg)
}

type Stream struct {
	mu              sync.Mutex
	upstreamQueue   [][]byte          // Данные от клиента к удаленному серверу
	downstreamQueue [][]byte          // Данные от удаленного сервера к клиенту
	pendingChunks   map[uint32][]byte // Чанки по seq номеру (для переупорядочивания от клиента)
	nextSeq         uint32            // Следующий ожидаемый seq от клиента
	downstreamSeq   uint32            // Счетчик seq для отправки клиенту
	closed          bool
	connected       bool          // Флаг, что соединение уже установлено
	upstreamNotify  chan struct{} // Канал для уведомления о новых данных в upstream
}

type Session struct {
	mu         sync.Mutex
	aesKey     []byte
	streams    map[uint16]*Stream
	decSeq     uint64
	encSeq     uint64
	lastSeen   time.Time
	notifyData chan struct{} // Канал для уведомления о новых данных

	// Параметры производительности (получены от клиента или дефолтные)
	// Каждая сессия (по уникальному id) имеет свои параметры
	// Это позволяет нескольким клиентам работать одновременно с разными настройками
	pollTimeout  int
	chunkSize    int
	readTimeout  int
	maxQueueSize int
	paramsSet    bool // Флаг, что параметры уже установлены
}

var sessions sync.Map // string -> *Session

type UserConfig struct {
	Users      map[string]string `json:"users"`
	StaticPath string            `json:"static_path"`
	Routing    RoutingBlock      `json:"routing"`
}

func loadUsers(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		logError("Config file not found or unreadable: %v\n", err)
		return
	}
	var cfg UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		logError("Failed to parse config: %v\n", err) // Не падаем при релоаде, просто логируем
		return
	}

	newAuthDB := make(map[string]UserData)
	count := 0

	for name, keyHex := range cfg.Users {
		if len(keyHex) != 32 {
			log.Printf("Warning: User %s has invalid key length (must be 32 hex chars)", name)
			continue
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			log.Printf("Warning: User %s has invalid hex key", name)
			continue
		}

		// Вычисляем Hash от ключа для идентификации
		sum := sha256.Sum256(key)
		authID := hex.EncodeToString(sum[:])[:16]
		log.Printf("Loaded user %s: authID=%s, key=%s", name, authID, keyHex)

		newAuthDB[authID] = UserData{
			Name: name,
			Key:  key,
		}
		count++
	}

	// Компилируем правила маршрутизации
	var compiled []compiledRule
	for _, r := range cfg.Routing.Rules {
		cr := compiledRule{
			typ:      r.Type,
			pattern:  r.Pattern,
			upstream: r.Upstream,
		}
		if r.Type == "regex" && r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				log.Printf("Routing: bad regex %q: %v", r.Pattern, err)
				continue
			}
			cr.re = re
		} else if r.Type == "list" && r.ListFile != "" {
			// Загружаем список доменов из файла
			domains, err := loadDomainList(r.ListFile)
			if err != nil {
				log.Printf("Routing: failed to load list file %q: %v", r.ListFile, err)
				continue
			}
			// Разделяем домены на точные и суффиксы
			cr.listDomains = make(map[string]bool)
			cr.listSuffixes = make([]string, 0)
			for domain := range domains {
				if strings.HasPrefix(domain, ".") {
					cr.listSuffixes = append(cr.listSuffixes, domain)
				} else {
					cr.listDomains[domain] = true
				}
			}
			log.Printf("Routing: loaded %d domains (%d exact, %d suffixes) from list file %q",
				len(domains), len(cr.listDomains), len(cr.listSuffixes), r.ListFile)
		}
		compiled = append(compiled, cr)
	}

	authMu.Lock()
	authDB = newAuthDB
	staticIndexPath = cfg.StaticPath
	authMu.Unlock()

	routingMu.Lock()
	routingRules = compiled
	routingMu.Unlock()

	logAlways("Loaded %d users from config\n", count)
	if staticIndexPath != "" {
		logAlways("Static index path: %s\n", staticIndexPath)
	}
	if len(routingRules) > 0 {
		logAlways("Loaded %d routing rules\n", len(routingRules))
	}
}

// loadDomainList загружает список доменов из файла (поддерживает текстовые и бинарные форматы)
func loadDomainList(filePath string) (map[string]bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	domains := make(map[string]bool)

	// Пытаемся определить формат файла
	// Проверяем, является ли файл валидным UTF-8 текстом
	isText := true
	if !bytes.HasPrefix(data, []byte{0xFF, 0xFE}) && !bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		// Проверяем, что файл содержит валидный UTF-8
		if !bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) { // BOM UTF-8
			// Пробуем декодировать как UTF-8
			if !isValidUTF8(data) {
				isText = false
			}
		}
	}

	if isText {
		// Текстовый формат: каждая строка = один домен
		// Декодируем как UTF-8 (поддерживает кириллицу)
		text := string(data)
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Пропускаем пустые строки и комментарии
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Убираем комментарии в конце строки
			if idx := strings.Index(line, "#"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line != "" {
				// Сохраняем домен как есть (может быть кириллица)
				domains[line] = true
				// Также сохраняем в Punycode для совместимости
				// (если домен содержит не-ASCII символы)
				if hasNonASCII(line) {
					punycode, err := idna.ToASCII(line)
					if err == nil && punycode != line {
						domains[punycode] = true
					}
				}
			}
		}
	} else {
		// Бинарный формат: домены разделены нулевым байтом или новой строкой
		// Обрабатываем как последовательность байтов
		var current []byte
		for i := 0; i < len(data); i++ {
			b := data[i]
			if b == 0 || b == '\n' || b == '\r' {
				// Разделитель найден, обрабатываем накопленный домен
				if len(current) > 0 {
					// Декодируем как UTF-8 (поддерживает кириллицу)
					domain := strings.TrimSpace(string(current))
					if domain != "" {
						domains[domain] = true
						// Также сохраняем в Punycode для совместимости
						if hasNonASCII(domain) {
							punycode, err := idna.ToASCII(domain)
							if err == nil && punycode != domain {
								domains[punycode] = true
							}
						}
					}
					current = nil
				}
				// Пропускаем последовательные разделители
				if b == '\r' && i+1 < len(data) && data[i+1] == '\n' {
					i++ // Пропускаем \n после \r
				}
			} else {
				// Добавляем байт к текущему домену (поддерживает UTF-8, включая кириллицу)
				current = append(current, b)
			}
		}
		// Обрабатываем последний домен, если файл не заканчивается разделителем
		if len(current) > 0 {
			domain := strings.TrimSpace(string(current))
			if domain != "" {
				domains[domain] = true
				// Также сохраняем в Punycode для совместимости
				if hasNonASCII(domain) {
					punycode, err := idna.ToASCII(domain)
					if err == nil && punycode != domain {
						domains[punycode] = true
					}
				}
			}
		}
	}

	return domains, nil
}

// isValidUTF8 проверяет, является ли байтовый массив валидным UTF-8
func isValidUTF8(data []byte) bool {
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		data = data[size:]
	}
	return true
}

// hasNonASCII проверяет, содержит ли строка не-ASCII символы
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// normalizeDomain нормализует домен для сравнения (конвертирует IDN в Punycode если нужно)
func normalizeDomain(domain string) string {
	if hasNonASCII(domain) {
		// Домен содержит не-ASCII символы, конвертируем в Punycode
		punycode, err := idna.ToASCII(domain)
		if err == nil {
			return punycode
		}
	}
	return domain
}

// matchRouting подбирает подходящее правило для домена
func matchRouting(domain string) (upstream string, ok bool) {
	routingMu.RLock()
	defer routingMu.RUnlock()

	// Нормализуем домен (конвертируем IDN в Punycode если нужно)
	normalizedDomain := normalizeDomain(domain)

	for _, r := range routingRules {
		switch r.typ {
		case "exact":
			// Проверяем как оригинальный паттерн, так и нормализованный
			if domain == r.pattern || normalizedDomain == normalizeDomain(r.pattern) {
				return r.upstream, true
			}
		case "suffix":
			// Нормализуем паттерн и проверяем суффикс
			normalizedPattern := normalizeDomain(r.pattern)
			if strings.HasSuffix(domain, r.pattern) || strings.HasSuffix(normalizedDomain, normalizedPattern) {
				return r.upstream, true
			}
		case "regex":
			if r.re != nil && (r.re.MatchString(domain) || r.re.MatchString(normalizedDomain)) {
				return r.upstream, true
			}
		case "list":
			// Проверяем точное совпадение (оригинальный и нормализованный домен)
			if r.listDomains != nil {
				if r.listDomains[domain] || r.listDomains[normalizedDomain] {
					return r.upstream, true
				}
			}
			// Проверяем суффиксы (домены, начинающиеся с точки)
			for _, suffix := range r.listSuffixes {
				normalizedSuffix := normalizeDomain(suffix)
				if strings.HasSuffix(domain, suffix) || strings.HasSuffix(normalizedDomain, normalizedSuffix) {
					return r.upstream, true
				}
			}
		}
	}
	return "", false
}

// dialViaEGET создает подключение через другой eGET сервер
// Формат upstream: eget://host:port/path?user=USER&key=KEY
// или: http://host:port/tunnel?user=USER&key=KEY
func dialViaEGET(upstreamURL, target string) (net.Conn, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid eget upstream URL: %v", err)
	}

	// Извлекаем user и key из query параметров
	user := u.Query().Get("user")
	keyHex := u.Query().Get("key")
	if user == "" || keyHex == "" {
		return nil, fmt.Errorf("eget upstream requires user and key parameters")
	}

	// Вычисляем hash ключа для аутентификации
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid key for eget upstream")
	}
	keyHash := sha256.Sum256(key)
	authID := hex.EncodeToString(keyHash[:])[:16]

	// Формируем базовый URL туннеля
	baseURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
	if baseURL == "" || !strings.HasSuffix(baseURL, "/tunnel") {
		baseURL = strings.TrimSuffix(baseURL, "/") + "/tunnel"
	}

	// Создаем HTTP клиент
	httpClient := &http.Client{
		Timeout: 150 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: false,
		},
	}

	// Генерируем уникальный session ID
	sessionID := fmt.Sprintf("route_%d", atomic.AddUint64(&routingSessionCounter, 1))

	// Создаем eGET proxy connection
	conn := &egetProxyConn{
		httpClient:      httpClient,
		baseURL:         baseURL,
		sessionID:       sessionID,
		authID:          authID,
		key:             key,
		target:          target,
		encSeq:          0,
		decSeq:          0,
		upstreamQueue:   make([][]byte, 0),
		downstreamQueue: make([][]byte, 0),
		closed:          make(chan struct{}),
	}

	// Отправляем первый чанк с адресом target
	// Формат: seq (4) + streamID (2) + ATYP (1) + ADDR
	// Для упрощения используем streamID = 1
	streamID := uint16(1)

	// Парсим target (host:port)
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		port, _ = strconv.Atoi(portStr)
	}

	// Формируем адрес в формате SOCKS5
	var addrBytes []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		// IPv4
		addrBytes = make([]byte, 1+4+2)
		addrBytes[0] = 1 // ATYP IPv4
		copy(addrBytes[1:5], ip.To4())
		binary.BigEndian.PutUint16(addrBytes[5:7], uint16(port))
	} else {
		// Domain
		addrBytes = make([]byte, 1+1+len(host)+2)
		addrBytes[0] = 3 // ATYP Domain
		addrBytes[1] = byte(len(host))
		copy(addrBytes[2:2+len(host)], host)
		binary.BigEndian.PutUint16(addrBytes[2+len(host):2+len(host)+2], uint16(port))
	}

	firstChunk := make([]byte, 4+2+len(addrBytes))
	binary.BigEndian.PutUint32(firstChunk[:4], 0) // seq = 0
	binary.BigEndian.PutUint16(firstChunk[4:6], streamID)
	copy(firstChunk[6:], addrBytes)

	// Шифруем и отправляем
	enc := encrypt(firstChunk, 0, key)
	reqURL := fmt.Sprintf("%s?id=%s&user=%s&data=%s", baseURL, sessionID, authID, url.QueryEscape(enc))
	resp, err := httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to eget upstream: %v", err)
	}
	resp.Body.Close()

	// Запускаем горутины для отправки и получения данных
	go conn.upstreamLoop()
	go conn.downstreamLoop()

	return conn, nil
}

var routingSessionCounter uint64

// egetProxyConn реализует net.Conn для проксирования через другой eGET сервер
type egetProxyConn struct {
	httpClient      *http.Client
	baseURL         string
	sessionID       string
	authID          string
	key             []byte
	target          string
	encSeq          uint64
	decSeq          uint64
	upstreamQueue   [][]byte
	downstreamQueue [][]byte
	mu              sync.Mutex
	closed          chan struct{}
	readDeadline    time.Time
	writeDeadline   time.Time
}

func (c *egetProxyConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.downstreamQueue) == 0 {
		c.mu.Unlock()
		select {
		case <-c.closed:
			return 0, io.EOF
		case <-time.After(100 * time.Millisecond):
		}
		c.mu.Lock()
		if len(c.downstreamQueue) == 0 {
			continue
		}
	}

	data := c.downstreamQueue[0]
	c.downstreamQueue = c.downstreamQueue[1:]

	n = copy(b, data)
	if len(data) > n {
		// Остаток данных возвращаем в очередь
		c.downstreamQueue = append([][]byte{data[n:]}, c.downstreamQueue...)
	}
	return n, nil
}

func (c *egetProxyConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	c.upstreamQueue = append(c.upstreamQueue, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}

func (c *egetProxyConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	return nil
}

func (c *egetProxyConn) LocalAddr() net.Addr  { return nil }
func (c *egetProxyConn) RemoteAddr() net.Addr { return nil }
func (c *egetProxyConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}
func (c *egetProxyConn) SetReadDeadline(t time.Time) error  { c.readDeadline = t; return nil }
func (c *egetProxyConn) SetWriteDeadline(t time.Time) error { c.writeDeadline = t; return nil }

func (c *egetProxyConn) upstreamLoop() {
	streamID := uint16(1)
	seq := uint32(1)

	for {
		select {
		case <-c.closed:
			return
		default:
		}

		c.mu.Lock()
		if len(c.upstreamQueue) == 0 {
			c.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		data := c.upstreamQueue[0]
		c.upstreamQueue = c.upstreamQueue[1:]
		c.mu.Unlock()

		chunk := make([]byte, 4+2+len(data))
		binary.BigEndian.PutUint32(chunk[:4], seq)
		binary.BigEndian.PutUint16(chunk[4:6], streamID)
		copy(chunk[6:], data)

		enc := encrypt(chunk, c.encSeq, c.key)
		c.encSeq++

		reqURL := fmt.Sprintf("%s?id=%s&user=%s&data=%s", c.baseURL, c.sessionID, c.authID, url.QueryEscape(enc))
		c.httpClient.Get(reqURL)

		seq++
	}
}

func (c *egetProxyConn) downstreamLoop() {
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		pollURL := fmt.Sprintf("%s?id=%s&user=%s&poll=1", c.baseURL, c.sessionID, c.authID)
		resp, err := c.httpClient.Get(pollURL)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(body) == "NO_DATA" || len(body) == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		plain, ok := decrypt(string(body), &c.decSeq, c.key)
		if !ok {
			continue
		}

		// Парсим батч чанков
		offset := 0
		for offset < len(plain) {
			if len(plain[offset:]) < 8 {
				break
			}
			_ = binary.BigEndian.Uint16(plain[offset : offset+2]) // streamID
			offset += 2
			chunkSize := int(binary.BigEndian.Uint16(plain[offset : offset+2]))
			offset += 2
			_ = binary.BigEndian.Uint32(plain[offset : offset+4]) // seq
			offset += 4

			if len(plain[offset:]) < chunkSize {
				break
			}

			payload := plain[offset : offset+chunkSize]
			offset += chunkSize

			c.mu.Lock()
			c.downstreamQueue = append(c.downstreamQueue, payload)
			c.mu.Unlock()
		}
	}
}

// dialViaUpstream делает подключение к target через указанный upstream (socks5/direct/eget)
func dialViaUpstream(upstream, target string) (net.Conn, error) {
	if upstream == "" || upstream == "direct" {
		return net.DialTimeout("tcp", target, time.Duration(*dialTimeout)*time.Second)
	}

	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", target)
	case "eget", "http", "https":
		// Маршрутизация через другой eGET сервер
		// Формат: eget://host:port/path?user=USER&key=KEY
		// или: http://host:port/tunnel?user=USER&key=KEY
		return dialViaEGET(upstream, target)
	case "direct", "":
		return net.DialTimeout("tcp", target, time.Duration(*dialTimeout)*time.Second)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme: %s", u.Scheme)
	}
}

// getSession получает или создает сессию для клиента
// Механизм восстановления:
//   - Если сессия была удалена (таймаут 5 минут) или сервер перезапустился,
//     при следующем запросе клиента сессия автоматически создается заново через LoadOrStore
//   - Параметры производительности передаются клиентом в каждом запросе и устанавливаются при создании новой сессии
//   - Последовательности (decSeq/encSeq) начинаются с 0 в новой сессии, но автоматически обновляются
//     при получении данных благодаря логике в decrypt (принимает любой seq и обновляет счетчик)
//   - Клиент не требует перезапуска - восстановление происходит автоматически при следующем запросе
func getSession(id string, key []byte, params map[string]int) *Session {
	val, loaded := sessions.LoadOrStore(id, &Session{
		streams:    make(map[uint16]*Stream),
		lastSeen:   time.Now(),
		notifyData: make(chan struct{}, 1000), // Буферизированный канал
		aesKey:     key,
		// Дефолтные значения (будут перезаписаны, если клиент передал параметры)
		pollTimeout:  *pollTimeout,
		chunkSize:    *chunkSize,
		readTimeout:  *readTimeout,
		maxQueueSize: *maxQueueSize,
		paramsSet:    false,
	})
	s := val.(*Session)

	// Если сессия уже существовала, проверяем, совпадает ли ключ (защита от угона сессии)
	if loaded {
		if !bytes.Equal(s.aesKey, key) {
			return nil
		}
		logf("[Session] Reusing existing session %s\n", id)
	} else {
		logf("[Session] Created new session %s (recovery from timeout or server restart)\n", id)
	}

	// Устанавливаем или обновляем параметры от клиента (если они переданы)
	if params != nil {
		s.mu.Lock()
		updated := false
		if pollTimeout, ok := params["poll-timeout"]; ok && pollTimeout > 0 {
			if s.pollTimeout != pollTimeout {
				s.pollTimeout = pollTimeout
				updated = true
			}
		}
		if chunkSize, ok := params["chunk-size"]; ok && chunkSize > 0 {
			if s.chunkSize != chunkSize {
				s.chunkSize = chunkSize
				updated = true
			}
		}
		if readTimeout, ok := params["read-timeout"]; ok && readTimeout > 0 {
			if s.readTimeout != readTimeout {
				s.readTimeout = readTimeout
				updated = true
			}
		}
		if maxQueue, ok := params["max-queue"]; ok && maxQueue > 0 {
			if s.maxQueueSize != maxQueue {
				s.maxQueueSize = maxQueue
				updated = true
			}
		}
		if updated || !s.paramsSet {
			s.paramsSet = true
			logf("[Session] Parameters for session %s: poll-timeout=%d, chunk-size=%d, read-timeout=%d, max-queue=%d\n",
				id, s.pollTimeout, s.chunkSize, s.readTimeout, s.maxQueueSize)
		}
		s.mu.Unlock()
	}

	s.lastSeen = time.Now()
	return s
}

// getCryptoCache получает или создает кэш cipher объектов для ключа
func getCryptoCache(key []byte) (*cryptoCache, error) {
	keyHex := hex.EncodeToString(key)

	// Пытаемся получить из кэша
	if val, ok := cryptoCacheMap.Load(keyHex); ok {
		return val.(*cryptoCache), nil
	}

	// Создаем новый
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	cache := &cryptoCache{
		block: block,
		gcm:   gcm,
	}

	// Сохраняем в кэш (если уже кто-то добавил, используем существующий)
	actual, _ := cryptoCacheMap.LoadOrStore(keyHex, cache)
	return actual.(*cryptoCache), nil
}

func encrypt(plain []byte, seq uint64, key []byte) string {
	cache, err := getCryptoCache(key)
	if err != nil {
		// Fallback на старый способ при ошибке
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[:8], seq)
		ct := gcm.Seal(nil, nonce, plain, nil)
		full := append(nonce, ct...)
		return base64.RawStdEncoding.EncodeToString(full)
	}

	// Создаем nonce (не используем пул, так как он становится частью результата)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[:8], seq)

	ct := cache.gcm.Seal(nil, nonce, plain, nil)
	full := append(nonce, ct...)
	return base64.RawStdEncoding.EncodeToString(full)
}

func decrypt(b64str string, expectedSeq *uint64, key []byte) ([]byte, bool) {
	// Декодируем base64 (используем стандартный метод, пул буферов не очень помогает для base64)
	data, err := base64.RawStdEncoding.DecodeString(b64str)
	if err != nil || len(data) < 28 {
		return nil, false
	}

	nonce := data[:12]
	ct := data[12:]

	cache, err := getCryptoCache(key)
	if err != nil {
		// Fallback на старый способ
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, false
		}
		if expectedSeq != nil {
			seq := binary.BigEndian.Uint64(nonce[:8])
			if seq >= *expectedSeq {
				*expectedSeq = seq + 1
			}
		}
		return plain, true
	}

	plain, err := cache.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, false
	}

	// Извлекаем последовательность из nonce для отслеживания
	if expectedSeq != nil {
		seq := binary.BigEndian.Uint64(nonce[:8])
		if seq >= *expectedSeq {
			*expectedSeq = seq + 1
		}
	}

	return plain, true
}

// Обработка одного чанка
func processChunk(s *Session, plain []byte) {
	if len(plain) < 6 {
		return
	}

	seq := binary.BigEndian.Uint32(plain[:4])
	streamID := binary.BigEndian.Uint16(plain[4:6])
	payload := plain[6:]

	s.mu.Lock()
	stream, exists := s.streams[streamID]
	if !exists {
		// Создаем новый стрим
		stream = &Stream{
			pendingChunks:  make(map[uint32][]byte),
			nextSeq:        0,
			upstreamNotify: make(chan struct{}, 1), // Буферизованный канал для уведомлений
		}
		s.streams[streamID] = stream
	}
	s.mu.Unlock()

	stream.mu.Lock()

	// Если стрим закрыт, игнорируем
	if stream.closed {
		stream.mu.Unlock()
		return
	}

	// Пустой payload с seq > 0 = сигнал закрытия
	if len(payload) == 0 && seq > 0 {
		stream.closed = true
		stream.mu.Unlock()
		return
	}

	// Сохраняем чанк по seq номеру
	if seq >= stream.nextSeq {
		stream.pendingChunks[seq] = payload
	}

	// Обрабатываем чанки по порядку
	needsRemoteConnection := false
	var addressPayload []byte
	processedSeq := stream.nextSeq

	for {
		chunk, ok := stream.pendingChunks[processedSeq]
		if !ok {
			break // Ждем следующий по порядку чанк
		}
		delete(stream.pendingChunks, processedSeq)

		if processedSeq == 0 {
			// Первый чанк (seq=0) содержит адрес
			if len(chunk) >= 3 {
				atyp := chunk[0]
				if atyp == 1 || atyp == 3 {
					stream.connected = true
					needsRemoteConnection = true
					addressPayload = chunk
				} else {
					stream.closed = true
					break
				}
			} else {
				stream.closed = true
				break
			}
		} else {
			// Последующие чанки - данные
			if stream.connected && len(chunk) > 0 {
				stream.upstreamQueue = append(stream.upstreamQueue, chunk)
				// Уведомляем upstream горутину о новых данных (неблокирующе)
				select {
				case stream.upstreamNotify <- struct{}{}:
				default:
					// Канал уже содержит уведомление
				}
			}
		}
		processedSeq++
	}

	// Обновляем nextSeq только после успешной обработки всех чанков
	stream.nextSeq = processedSeq

	stream.mu.Unlock()

	// Запускаем соединение после освобождения lock
	if needsRemoteConnection {
		logAlways("[+] Stream %d connecting...\n", streamID)
		logf("[+] Stream %d connecting...\n", streamID)
		go handleRemoteConnection(s, streamID, addressPayload)
	}
}

func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	// Логируем полный URL для отладки
	fullURL := r.URL.String()
	if len(fullURL) > 200 {
		fullURL = fullURL[:200] + "..."
	}
	logAlways("[Request] %s %s (has data param: %v)\n", r.Method, fullURL, r.URL.Query().Has("data"))
	logf("[Request] %s %s?%s\n", r.Method, r.URL.Path, r.URL.RawQuery)

	// Автоматически поддерживаем и GET, и PUT запросы
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		logError("[Error] Method not allowed: %s\n", r.Method)
		http.Error(w, "Only GET or PUT allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		logError("[Error] Missing session id\n")
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	// user параметр теперь содержит хеш ключа, а не имя
	authID := r.URL.Query().Get("user")
	if authID == "" {
		http.Error(w, "missing auth id", http.StatusUnauthorized)
		return
	}

	authMu.RLock()
	userData, ok := authDB[authID]
	authMu.RUnlock()

	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	logf("[Auth] User authID=%s, key len=%d\n", authID, len(userData.Key))

	// Извлекаем параметры производительности из query (если переданы клиентом)
	params := make(map[string]int)
	if pollTimeoutStr := r.URL.Query().Get("poll-timeout"); pollTimeoutStr != "" {
		if val, err := strconv.Atoi(pollTimeoutStr); err == nil && val > 0 {
			params["poll-timeout"] = val
		}
	}
	if chunkSizeStr := r.URL.Query().Get("chunk-size"); chunkSizeStr != "" {
		if val, err := strconv.Atoi(chunkSizeStr); err == nil && val > 0 {
			params["chunk-size"] = val
		}
	}
	if readTimeoutStr := r.URL.Query().Get("read-timeout"); readTimeoutStr != "" {
		if val, err := strconv.Atoi(readTimeoutStr); err == nil && val > 0 {
			params["read-timeout"] = val
		}
	}
	if maxQueueStr := r.URL.Query().Get("max-queue"); maxQueueStr != "" {
		if val, err := strconv.Atoi(maxQueueStr); err == nil && val > 0 {
			params["max-queue"] = val
		}
	}

	s := getSession(id, userData.Key, params)
	if s == nil {
		logError("[Auth] Session creation failed for id=%s\n", id)
		http.Error(w, "session unauthorized or invalid", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, private")

	var data string
	if r.Method == http.MethodPut {
		// Читаем все данные из тела запроса
		// HTTP chunked encoding автоматически декодируется Go, мы получаем чистые данные
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			logError("[Error] Failed to read PUT body: %v\n", err)
			return
		}

		// Парсим несколько зашифрованных блоков, разделенных "\x00\x00\x00\x00"
		separator := []byte{0, 0, 0, 0}
		bodyStr := string(bodyBytes)

		// Если есть разделитель, обрабатываем несколько блоков (chunked mode)
		if bytes.Contains(bodyBytes, separator) {
			blocks := bytes.Split(bodyBytes, separator)
			logAlways("[Data] Got PUT chunked data: %d blocks, total len=%d\n", len(blocks), len(bodyBytes))

			// Обрабатываем каждый блок отдельно
			for i, block := range blocks {
				if len(block) == 0 {
					continue
				}
				blockStr := string(block)
				logf("[Data] Processing chunked block %d, len=%d\n", i+1, len(blockStr))

				// Расшифровываем и обрабатываем блок
				plain, ok := decrypt(blockStr, &s.decSeq, s.aesKey)
				if !ok || len(plain) < 6 {
					logError("[Error] Failed to decrypt chunked block %d for session %s (plain len=%d, ok=%v)\n", i+1, id, len(plain), ok)
					continue
				}
				logAlways("[Data] Decrypted chunked block %d successfully, plain len=%d\n", i+1, len(plain))
				processChunk(s, plain)
			}

			// Отправляем ответ после обработки всех блоков
			logAlways("[Data] Processed all chunked blocks, sending OK response\n")
			n, err := w.Write([]byte("OK"))
			if err != nil {
				logError("[Error] Failed to write OK response: %v\n", err)
			} else {
				logAlways("[Data] Successfully sent OK response, %d bytes\n", n)
			}
			return
		}

		// Один блок - обычная обработка
		data = bodyStr
		logAlways("[Data] Got PUT data (single block), len=%d\n", len(data))
	} else {
		// Проверяем, есть ли параметр data в URL
		hasData := r.URL.Query().Has("data")
		data = r.URL.Query().Get("data")
		if hasData && data == "" {
			// Параметр есть, но пустой - возможно проблема с URL-кодированием
			// Пробуем получить из RawQuery напрямую
			logAlways("[Data] WARNING: data param exists but is empty! RawQuery len=%d\n", len(r.URL.RawQuery))
			// Пробуем извлечь вручную из RawQuery
			rawQuery := r.URL.RawQuery
			if idx := strings.Index(rawQuery, "data="); idx >= 0 {
				value := rawQuery[idx+5:]
				if ampIdx := strings.Index(value, "&"); ampIdx >= 0 {
					value = value[:ampIdx]
				}
				if value != "" {
					decoded, err := url.QueryUnescape(value)
					if err == nil {
						data = decoded
						logAlways("[Data] Extracted data from RawQuery, len=%d\n", len(data))
					}
				}
			}
		}
		logAlways("[Data] Got GET data param, len=%d, empty=%v, hasParam=%v\n", len(data), data == "", hasData)
	}

	if data != "" {
		logAlways("[Data] Received data chunk, len=%d, session=%s\n", len(data), id)
		plain, ok := decrypt(data, &s.decSeq, s.aesKey)
		// Новый формат: seq (4) + streamID (2) + payload
		if !ok || len(plain) < 6 {
			logError("[Error] Failed to decrypt data for session %s (plain len=%d, ok=%v)\n", id, len(plain), ok)
			return
		}
		logAlways("[Data] Decrypted successfully, plain len=%d\n", len(plain))
		processChunk(s, plain)
		logAlways("[Data] Processed chunk, sending OK response\n")
		n, err := w.Write([]byte("OK"))
		if err != nil {
			logError("[Error] Failed to write OK response: %v\n", err)
		} else {
			logAlways("[Data] Successfully sent OK response, %d bytes\n", n)
		}
		return
	}

	poll := r.URL.Query().Get("poll") == "1"
	if poll {
		logAlways("[Poll] Poll request from session %s\n", id)
		logf("[Poll] Poll request from session %s\n", id)

		// Функция проверки наличия данных во всех стримах
		// Оптимизировано: минимизировано время блокировки мьютекса сессии
		// ИСПРАВЛЕНО: обрабатываем стримы по одному, чтобы избежать блокировок
		checkData := func() ([]byte, bool) {
			var selectedChunks []byte
			totalSize := 0
			maxBatchSize := 16 * 1024 // Максимум 16KB за один запрос (меньше для CDN)

			// Сначала быстро собираем список ID стримов (без блокировки стримов)
			var streamIDs []uint16
			s.mu.Lock()
			for sid := range s.streams {
				streamIDs = append(streamIDs, sid)
			}
			s.mu.Unlock() // Освобождаем мьютекс сессии как можно быстрее

			// Теперь обрабатываем стримы по одному (блокируем только один стрим за раз)
			for _, sid := range streamIDs {
				if totalSize >= maxBatchSize {
					break
				}

				// Получаем стрим и блокируем его
				s.mu.Lock()
				st, exists := s.streams[sid]
				if !exists {
					s.mu.Unlock()
					continue
				}
				// Блокируем стрим
				st.mu.Lock()
				s.mu.Unlock() // Освобождаем мьютекс сессии сразу после получения стрима

				// Проверяем, есть ли данные
				if len(st.downstreamQueue) == 0 {
					st.mu.Unlock()
					continue
				}

				// Берем чанки из этого стрима пока не достигнем лимита
				for len(st.downstreamQueue) > 0 && totalSize < maxBatchSize {
					chunk := st.downstreamQueue[0]
					chunkSize := 2 + 2 + 4 + len(chunk)

					if totalSize == 0 {
						selectedChunks = make([]byte, 0, maxBatchSize)
					}

					if totalSize+chunkSize > maxBatchSize {
						break
					}

					// Добавляем streamID, размер, seq и данные
					header := make([]byte, 8)
					binary.BigEndian.PutUint16(header[0:2], sid)
					binary.BigEndian.PutUint16(header[2:4], uint16(len(chunk)))
					binary.BigEndian.PutUint32(header[4:8], st.downstreamSeq)
					st.downstreamSeq++

					selectedChunks = append(selectedChunks, header...)
					selectedChunks = append(selectedChunks, chunk...)
					totalSize += chunkSize

					// Удаляем из очереди
					st.downstreamQueue = st.downstreamQueue[1:]
				}
				st.mu.Unlock()

				if totalSize > 0 {
					break // Нашли данные, выходим
				}
			}

			if totalSize > 0 {
				return selectedChunks, true
			}
			return nil, false
		}

		// Сразу проверяем, есть ли данные (без ожидания)
		s.mu.Lock()
		streamCount := len(s.streams)
		s.mu.Unlock()
		logAlways("[Poll] Checking for data in session %s (streams: %d)\n", id, streamCount)
		logf("[Poll] Checking for data in session %s (streams: %d)\n", id, streamCount)

		// Если нет активных стримов, сразу возвращаем NO_DATA (не ждем таймаут)
		s.mu.Lock()
		hasActiveStreams := len(s.streams) > 0
		s.mu.Unlock()

		if !hasActiveStreams {
			logAlways("[Poll] No active streams, sending NO_DATA immediately\n")
			logf("[Poll] No active streams, sending NO_DATA immediately\n")
			w.Write([]byte("NO_DATA"))
			return
		}

		if data, ok := checkData(); ok {
			logAlways("[Poll] Sending data: plain len=%d, seq=%d\n", len(data), s.encSeq)
			logf("[Poll] Sending data: plain len=%d, seq=%d, key len=%d\n", len(data), s.encSeq, len(s.aesKey))
			enc := encrypt(data, s.encSeq, s.aesKey)
			s.encSeq++
			logAlways("[Poll] Encrypted data: len=%d, writing to response\n", len(enc))
			logf("[Poll] Encrypted data: len=%d, seq=%d, writing to response\n", len(enc), s.encSeq-1)
			n, err := w.Write([]byte(enc))
			if err != nil {
				logError("[Poll] Error writing response: %v\n", err)
			} else {
				logAlways("[Poll] Successfully wrote %d bytes to response\n", n)
				logf("[Poll] Successfully wrote %d bytes to response\n", n)
			}
			return
		}

		s.mu.Lock()
		sessionPollTimeout := s.pollTimeout
		s.mu.Unlock()

		logf("[Poll] No data available, waiting for timeout or notifyData (timeout: %ds)\n", sessionPollTimeout)

		// Используем более короткий таймаут для CDN (но не меньше 3 секунд)
		cdnTimeout := time.Duration(sessionPollTimeout) * time.Second
		if cdnTimeout > 10*time.Second {
			cdnTimeout = 10 * time.Second // Максимум 10 секунд для CDN
		}
		pollTimeoutChan := time.After(cdnTimeout)

		logAlways("[Poll] Entering wait loop, timeout=%ds\n", sessionPollTimeout)
		for {
			select {
			case <-pollTimeoutChan:
				logAlways("[Poll] Timeout, sending NO_DATA\n")
				logf("[Poll] Timeout, sending NO_DATA\n")
				w.Write([]byte("NO_DATA"))
				return
			case <-s.notifyData:
				logAlways("[Poll] Got notifyData signal, checking for data\n")
				// Получили сигнал, проверяем данные
				if data, ok := checkData(); ok {
					logAlways("[Poll] Got notifyData, sending data: plain len=%d, seq=%d\n", len(data), s.encSeq)
					logf("[Poll] Got notifyData, sending data: plain len=%d, seq=%d\n", len(data), s.encSeq)
					enc := encrypt(data, s.encSeq, s.aesKey)
					s.encSeq++
					logAlways("[Poll] Encrypted data: len=%d, writing to response\n", len(enc))
					logf("[Poll] Encrypted data: len=%d, seq=%d, writing to response\n", len(enc), s.encSeq-1)
					n, err := w.Write([]byte(enc))
					if err != nil {
						logError("[Poll] Error writing response: %v\n", err)
					} else {
						logAlways("[Poll] Successfully wrote %d bytes to response\n", n)
						logf("[Poll] Successfully wrote %d bytes to response\n", n)
					}

					// Если в канале еще есть сигналы (много данных пришло),
					// они останутся для следующих поллеров
					return
				} else {
					logAlways("[Poll] Got notifyData but no data available, continuing wait\n")
				}
			}
		}
	}

	// Проверяем запрос на закрытие сессии
	if r.URL.Query().Get("close") == "1" {
		logf("[Session] Close request for session %s\n", id)
		s.mu.Lock()
		// Закрываем все стримы сессии
		for streamID, stream := range s.streams {
			stream.mu.Lock()
			if !stream.closed {
				stream.closed = true
				logf("[Session] Closed stream %d in session %s\n", streamID, id)
			}
			stream.mu.Unlock()
		}
		// Удаляем сессию
		sessions.Delete(id)
		s.mu.Unlock()
		logf("[Session] Session %s closed and removed\n", id)
		w.Write([]byte("OK"))
		return
	}

	logf("[Request] Returning OK\n")
	w.Write([]byte("OK"))
}

func handleRemoteConnection(s *Session, streamID uint16, firstPayload []byte) {
	if len(firstPayload) < 3 {
		// Первый чанк может быть пустым (только streamID), ждем следующий
		if len(firstPayload) == 2 {
			// Только streamID, нет данных адреса - это нормально, ждем следующий чанк
			return
		}
		logError("[Error] Invalid address in first chunk for stream %d, len=%d\n", streamID, len(firstPayload))
		return
	}

	var target string
	var domain string
	var initialData []byte
	offset := 0
	atyp := firstPayload[offset]
	offset++

	switch atyp {
	case 1: // IPv4
		if len(firstPayload[offset:]) < 6 {
			return
		}
		ip := net.IP(firstPayload[offset : offset+4])
		port := binary.BigEndian.Uint16(firstPayload[offset+4 : offset+6])
		target = fmt.Sprintf("%s:%d", ip.String(), port)
		offset += 6
		logf("[→] Stream %d: IPv4 → %s\n", streamID, target)
	case 3: // Domain
		if len(firstPayload[offset:]) < 1 {
			return
		}
		domainLen := int(firstPayload[offset])
		offset++
		if len(firstPayload[offset:]) < domainLen+2 {
			return
		}
		domain = string(firstPayload[offset : offset+domainLen])
		port := binary.BigEndian.Uint16(firstPayload[offset+domainLen : offset+domainLen+2])
		target = fmt.Sprintf("%s:%d", domain, port)
		offset += domainLen + 2
		logf("[→] Stream %d: Domain → %s\n", streamID, target)
	default:
		logError("[Error] Unsupported ATYP %d for stream %d\n", atyp, streamID)
		return
	}

	// Данные после адреса в первом чанке (обычно пусто, но на всякий)
	initialData = firstPayload[offset:]

	// Маршрутизация по домену (если есть)
	var remote net.Conn
	var err error
	if domain != "" {
		if upstream, ok := matchRouting(domain); ok {
			logf("[→] Routing %s → %s\n", domain, upstream)
			remote, err = dialViaUpstream(upstream, target)
		} else {
			remote, err = net.DialTimeout("tcp", target, time.Duration(*dialTimeout)*time.Second)
		}
	} else {
		remote, err = net.DialTimeout("tcp", target, time.Duration(*dialTimeout)*time.Second)
	}
	if err != nil {
		logError("[Error] Failed to connect to %s: %v\n", target, err)
		// Отправляем ошибку клиенту через downstream очередь
		s.mu.Lock()
		stream, exists := s.streams[streamID]
		if exists && stream != nil {
			// Помечаем стрим как закрытый
			stream.closed = true
		}
		s.mu.Unlock()
		return
	}
	defer remote.Close()

	// Получаем stream с проверкой
	s.mu.Lock()
	stream, exists := s.streams[streamID]
	s.mu.Unlock()

	if !exists || stream == nil {
		// Стрим был удален до установки соединения
		return
	}

	// Если в первом чанке были данные — сразу шлём
	if len(initialData) > 0 {
		remote.Write(initialData)
	}

	// Upstream: очередь → remote
	// Оптимизировано: убран sleep, используется канал для уведомлений
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		for {
			stream.mu.Lock()
			if stream.closed && len(stream.upstreamQueue) == 0 {
				stream.mu.Unlock()
				return
			}
			if len(stream.upstreamQueue) > 0 {
				data := stream.upstreamQueue[0]
				stream.upstreamQueue = stream.upstreamQueue[1:]
				stream.mu.Unlock()

				_, err := remote.Write(data)
				if err != nil {
					stream.mu.Lock()
					stream.closed = true
					stream.mu.Unlock()
					return
				}
			} else {
				stream.mu.Unlock()
				// Ждем уведомления о новых данных вместо sleep
				select {
				case <-stream.upstreamNotify:
					// Есть новые данные, продолжаем цикл
				case <-time.After(10 * time.Millisecond):
					// Таймаут для проверки закрытия (на случай если уведомление потеряно)
					continue
				}
			}
		}
	}()

	// Downstream: remote → очередь
	s.mu.Lock()
	sessionChunkSize := s.chunkSize
	sessionReadTimeout := s.readTimeout
	sessionMaxQueue := s.maxQueueSize
	s.mu.Unlock()

	buf := make([]byte, sessionChunkSize)
	maxQueue := sessionMaxQueue
	totalRead := 0
	for {
		remote.SetReadDeadline(time.Now().Add(time.Duration(sessionReadTimeout) * time.Second))

		// Проверяем размер очереди перед чтением
		stream.mu.Lock()
		queueSize := len(stream.downstreamQueue)
		isClosed := stream.closed
		stream.mu.Unlock()

		if isClosed {
			break
		}

		if queueSize >= maxQueue {
			// Очередь переполнена, ждем пока poll заберет данные
			time.Sleep(1 * time.Millisecond)
			continue
		}

		n, err := remote.Read(buf)
		if n > 0 {
			totalRead += n
			// Оптимизация: создаем слайс напрямую из буфера вместо копирования
			// Это безопасно, так как данные сразу добавляются в очередь
			data := make([]byte, n)
			copy(data, buf[:n]) // Копируем, так как buf переиспользуется

			stream.mu.Lock()
			if !stream.closed {
				stream.downstreamQueue = append(stream.downstreamQueue, data)
				// Уведомляем poll, что есть новые данные
				select {
				case s.notifyData <- struct{}{}:
				default:
					// Канал полон, это нормально - значит поллеры уже уведомлены
				}
			}
			stream.mu.Unlock()
		}
		if err != nil {
			if err == io.EOF {
				logf("[↓] Stream %d: EOF после %.1f KB\n", streamID, float64(totalRead)/1024)
			} else {
				logf("[!] Stream %d: ошибка чтения: %v (прочитано %.1f KB)\n", streamID, err, float64(totalRead)/1024)
			}
			break
		}
	}

	// ВАЖНО: Помечаем стрим как закрытый, но НЕ удаляем сразу
	// Данные в downstreamQueue должны быть отправлены клиенту
	stream.mu.Lock()
	stream.closed = true
	queueSize := len(stream.downstreamQueue)
	stream.mu.Unlock()

	logf("[↓] Stream %d: закрытие, осталось в очереди: %d чанков\n", streamID, queueSize)

	// Ждем завершения upstream горутины
	<-upstreamDone

	// Ждем пока все данные из очереди будут отправлены клиенту
	// Проверяем каждые 10мс, максимум 5 секунд
	maxWaitTime := 5 * time.Second
	checkInterval := 10 * time.Millisecond
	waited := time.Duration(0)
	for waited < maxWaitTime {
		stream.mu.Lock()
		queueSize = len(stream.downstreamQueue)
		stream.mu.Unlock()
		if queueSize == 0 {
			break // Все данные отправлены
		}
		time.Sleep(checkInterval)
		waited += checkInterval
	}

	if queueSize > 0 {
		logf("[!] Stream %d: закрыт, но осталось %d чанков в очереди (не отправлены)\n", streamID, queueSize)
	}

	// Удаляем стрим из map только после отправки всех данных
	s.mu.Lock()
	delete(s.streams, streamID)
	s.mu.Unlock()

	logf("[-] Stream %d closed\n", streamID)
}

func cleanupSessions() {
	for {
		time.Sleep(60 * time.Second)
		now := time.Now()
		sessions.Range(func(key, value interface{}) bool {
			s := value.(*Session)
			s.mu.Lock()
			// Удаляем сессии старше 5 минут без активности
			if now.Sub(s.lastSeen) > 5*time.Minute {
				s.mu.Unlock()
				sessions.Delete(key)
				return true
			}
			// Удаляем закрытые стримы
			for sid, st := range s.streams {
				st.mu.Lock()
				if st.closed {
					delete(s.streams, sid)
				}
				st.mu.Unlock()
			}
			s.mu.Unlock()
			return true
		})
	}
}

func main() {
	flag.Parse()

	// Открываем файл для логирования
	var err error
	logFile, err = os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Записываем заголовок в лог
	logAlways("=== eGET Server started at %s ===\n", time.Now().Format("2006-01-02 15:04:05"))

	loadUsers(*configFile)

	fmt.Println("╔═══════════════════════════════════════════════════════╗")
	fmt.Println("║         eGET Server - HTTP Tunnel Gateway             ║")
	fmt.Println("╚═══════════════════════════════════════════════════════╝")
	fmt.Printf("Слушает: %s\n", *listen)
	fmt.Println("───────────────────────────────────────────────────────")
	fmt.Printf("Max queue:    %d чанков (дефолт, клиент может переопределить)\n", *maxQueueSize)
	fmt.Printf("Poll timeout: %d сек (дефолт, клиент может переопределить)\n", *pollTimeout)
	fmt.Printf("Poll interval: %d мкс\n", *pollInterval)
	fmt.Printf("Chunk size:   %d байт (дефолт, клиент может переопределить)\n", *chunkSize)
	fmt.Printf("Read timeout: %d сек (дефолт, клиент может переопределить)\n", *readTimeout)
	fmt.Printf("Dial timeout: %d сек\n", *dialTimeout)
	fmt.Printf("PID процесса: %d\n", os.Getpid())
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("ℹ Сервер автоматически подхватывает параметры от клиента")
	fmt.Println("═══════════════════════════════════════════════════════")

	// Запускаем очистку старых сессий
	go cleanupSessions()

	// Обработка сигналов для reload (SIGHUP)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			logAlways("Received SIGHUP, reloading users...\n")
			loadUsers(*configFile)
		}
	}()

	http.HandleFunc("/tunnel", tunnelHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		// Пытаемся отдать статический index.html, если путь указан в конфиге
		authMu.RLock()
		indexPath := staticIndexPath
		authMu.RUnlock()

		if indexPath != "" {
			if data, err := os.ReadFile(indexPath); err == nil {
				_, _ = w.Write(data)
				return
			} else {
				logError("[Error] Failed to read static index %s: %v\n", indexPath, err)
			}
		}

		// Фолбэк: встроенная простая заглушка
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>__main__</title>
</head>
<body>
  <h1>__init__</h1>
  <p>0000000000000000000000000000032</p>
  <p>gBPMw@ZJR4yBdghHb?O6h*geP~YJTu <code>0x80</code></p>
</body>
</html>`)
	})

	logAlways("eGET server started on %s\n", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
