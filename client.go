package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	server     = flag.String("server", "", "URL сервера (например: http://example.com/tunnel)")
	id         = flag.String("id", "default", "ID сессии")
	userFlag   = flag.String("user", "", "Имя пользователя")
	keyFlag    = flag.String("key", "", "Ключ шифрования (hex)")
	listen     = flag.String("listen", "127.0.0.1:1080", "Адрес SOCKS5 прокси")
	usePut     = flag.Bool("put", false, "Использовать PUT для отправки данных")
	useChunked = flag.Bool("chunked", false, "Использовать chunked transfer encoding для PUT (отправка нескольких чанков в одном запросе)")
	serverHost = flag.String("server-host", "", "Переопределить HTTP Host (XHTTP-подобный режим, например: front.domain.com)")

	pollers          = flag.Int("pollers", 16, "Количество параллельных поллеров")
	pollInterval     = flag.Int("poll-interval", 100, "Пауза при NO_DATA в микросекундах")
	chunkSize        = flag.Int("chunk-size", 8192, "Размер чанков в байтах (8192 = 8KB рекомендуется для CDN)")
	httpTimeout      = flag.Int("timeout", 20, "HTTP timeout в секундах (рекомендуется 15-20 для CDN)")
	maxIdleConns     = flag.Int("max-idle-conns", 300, "Максимум idle соединений")
	maxIdleConnsHost = flag.Int("max-idle-conns-host", 50, "Максимум idle соединений на хост")
	readTimeout      = flag.Int("read-timeout", 600, "Timeout чтения из socket в секундах")
	maxQueue         = flag.Int("max-queue", 1500, "Максимальный размер очереди чанков на сервере")
	pollTimeout      = flag.Int("poll-timeout", 10, "Timeout для poll запросов на сервере в секундах")
	verbose          = flag.Bool("verbose", false, "Включить подробное логирование")
)

func logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logMu.Lock()
	if logFile != nil {
		logFile.WriteString(msg)
		logFile.Sync()
	}
	logMu.Unlock()
	fmt.Print(msg)
}

func logf(format string, args ...interface{}) {
	if *verbose {
		msg := fmt.Sprintf(format, args...)
		fmt.Print(msg)
	}
}

func logAlways(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cryptoCache кэширует cipher объекты для переиспользования
type cryptoCache struct {
	block cipher.Block
	gcm   cipher.AEAD
}

var (
	serverURL    string
	sessionID    string
	user         string
	aesKey       []byte
	encSeq       uint64
	mu           sync.Mutex
	serverAlive  bool
	httpClient   *http.Client
	overrideHost string
	logFile      *os.File
	logMu        sync.Mutex

	cryptoCacheOnce sync.Once
	cryptoCacheInst *cryptoCache

	noncePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 12)
		},
	}
)

type Stream struct {
	mu                sync.Mutex
	localConn         net.Conn
	closed            bool
	seq               uint32
	nextDownstreamSeq uint32
	pendingChunks     map[uint32][]byte
	downloadedBytes   int
	sendQueue         chan []byte
	sendErr           error
}

var (
	streams       sync.Map
	streamCounter uint32
	streamNotify  chan struct{}
)

func init() {
	streamNotify = make(chan struct{}, 100)

	httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:          *maxIdleConns,
			MaxIdleConnsPerHost:   *maxIdleConnsHost,
			IdleConnTimeout:       120 * time.Second,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: time.Duration(*httpTimeout) * time.Second,
			MaxConnsPerHost:       0,
			DisableCompression:    true,
			WriteBufferSize:       128 * 1024,
			ReadBufferSize:        128 * 1024,
		},
		Timeout: time.Duration(*httpTimeout) * time.Second,
	}
}

func buildURL(base string, poll bool, closeSession bool) string {
	u := fmt.Sprintf("%s?id=%s&user=%s", base, sessionID, user)
	if poll {
		u += "&poll=1"
	}
	if closeSession {
		u += "&close=1"
	}
	u += fmt.Sprintf("&poll-timeout=%d&chunk-size=%d&read-timeout=%d&max-queue=%d",
		*pollTimeout,
		*chunkSize,
		*readTimeout,
		*maxQueue,
	)
	return u
}

func checkServer() bool {
	u := buildURL(serverURL, false, false)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	if overrideHost != "" {
		req.Host = overrideHost
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return string(body) == "OK"
}

func healthMonitor() {
	for {
		alive := checkServer()
		if alive != serverAlive {
			serverAlive = alive
			status := "недоступен ✗"
			if alive {
				status = "доступен ✓"
			}
			logf("[Health] Сервер %s\n", status)
		}
		time.Sleep(30 * time.Second)
	}
}

func nextStreamID() uint16 {
	newID := atomic.AddUint32(&streamCounter, 1)
	id := uint16(newID % 65535)
	if id == 0 {
		id = 1
	}
	return id
}

func getCryptoCache() *cryptoCache {
	if aesKey == nil {
		return nil
	}

	cryptoCacheOnce.Do(func() {
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return
		}
		cryptoCacheInst = &cryptoCache{
			block: block,
			gcm:   gcm,
		}
	})

	return cryptoCacheInst
}

func encrypt(plain []byte) string {
	if aesKey == nil {
		return base64.RawStdEncoding.EncodeToString(plain)
	}

	cache := getCryptoCache()
	if cache == nil {
		// Fallback на старый способ
		block, _ := aes.NewCipher(aesKey)
		gcm, _ := cipher.NewGCM(block)
		mu.Lock()
		seq := encSeq
		encSeq++
		mu.Unlock()
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint64(nonce[:8], seq)
		ct := gcm.Seal(nil, nonce, plain, nil)
		full := append(nonce, ct...)
		return base64.RawStdEncoding.EncodeToString(full)
	}

	mu.Lock()
	seq := encSeq
	encSeq++
	mu.Unlock()

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[:8], seq)

	ct := cache.gcm.Seal(nil, nonce, plain, nil)
	full := append(nonce, ct...)

	return base64.RawStdEncoding.EncodeToString(full)
}

func decrypt(b64str string) ([]byte, bool) {
	data, err := base64.RawStdEncoding.DecodeString(b64str)
	if err != nil {
		logError("[Decrypt] Base64 decode error: %v\n", err)
		return nil, false
	}
	if len(data) < 28 {
		logf("[Decrypt] Data too short: %d bytes (need at least 28)\n", len(data))
		return nil, false
	}

	if aesKey == nil {
		return data, true
	}

	nonce := data[:12]
	ct := data[12:]
	seq := binary.BigEndian.Uint64(nonce[:8])
	logf("[Decrypt] Attempting decrypt: data len=%d, nonce seq=%d, key len=%d\n", len(data), seq, len(aesKey))

	cache := getCryptoCache()
	if cache == nil {
		// Fallback на старый способ
		block, _ := aes.NewCipher(aesKey)
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			logError("[Decrypt] GCM Open error: %v (data len=%d, key len=%d, seq=%d)\n", err, len(data), len(aesKey), seq)
			return nil, false
		}
		logf("[Decrypt] Successfully decrypted %d bytes (seq=%d)\n", len(plain), seq)
		return plain, true
	}

	plain, err := cache.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		logError("[Decrypt] GCM Open error: %v (data len=%d, key len=%d, seq=%d)\n", err, len(data), len(aesKey), seq)
		return nil, false
	}
	logf("[Decrypt] Successfully decrypted %d bytes (seq=%d)\n", len(plain), seq)
	return plain, true
}

type chunkedWriter struct {
	chunks [][]byte
	mu     sync.Mutex
}

func (cw *chunkedWriter) Write(p []byte) (n int, err error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	chunk := make([]byte, len(p))
	copy(chunk, p)
	cw.chunks = append(cw.chunks, chunk)
	return len(p), nil
}

func (cw *chunkedWriter) Flush() [][]byte {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	chunks := cw.chunks
	cw.chunks = nil
	return chunks
}

var (
	chunkedQueue   = make(chan []byte, 1000)
	chunkedFlush   = make(chan struct{})
	chunkedEnabled = false
)

func sendChunksChunked(chunks [][]byte) error {
	if len(chunks) == 0 {
		return nil
	}

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		separator := []byte{0, 0, 0, 0}
		for i, chunk := range chunks {
			enc := encrypt(chunk)
			if i > 0 {
				if _, err := pw.Write(separator); err != nil {
					logError("[Send] Error writing separator to pipe: %v\n", err)
					return
				}
			}
			if _, err := pw.Write([]byte(enc)); err != nil {
				logError("[Send] Error writing data to pipe: %v\n", err)
				return
			}
		}
	}()

	u := buildURL(serverURL, false, false)
	req, err := http.NewRequest(http.MethodPut, u, pr)
	if err != nil {
		pr.Close()
		return err
	}
	if overrideHost != "" {
		req.Host = overrideHost
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		pr.Close()
		logError("[Send] Error sending chunked data: %v\n", err)
		return err
	}
	resp.Body.Close()
	logf("[Send] Sent %d chunks via chunked transfer\n", len(chunks))
	return nil
}

func chunkedSender() {
	batch := make([][]byte, 0, 10)
	batchTimeout := time.NewTicker(50 * time.Millisecond)
	defer batchTimeout.Stop()

	for {
		select {
		case chunk, ok := <-chunkedQueue:
			if !ok {
				// Канал закрыт, отправляем оставшиеся чанки
				if len(batch) > 0 {
					sendChunksChunked(batch)
				}
				return
			}
			batch = append(batch, chunk)
			// Если батч заполнен, отправляем сразу
			if len(batch) >= 10 {
				sendChunksChunked(batch)
				batch = batch[:0]
			}
		case <-batchTimeout.C:
			// Таймаут - отправляем накопленные чанки
			if len(batch) > 0 {
				sendChunksChunked(batch)
				batch = batch[:0]
			}
		case <-chunkedFlush:
			// Немедленная отправка
			if len(batch) > 0 {
				sendChunksChunked(batch)
				batch = batch[:0]
			}
		}
	}
}

func sendChunk(chunk []byte) error {
	if len(chunk) == 0 {
		return nil
	}
	logf("[Send] Sending chunk, len=%d\n", len(chunk))

	if *usePut && *useChunked {
		// Используем chunked transfer encoding - отправляем plain chunk, шифрование в sendChunksChunked
		chunkCopy := make([]byte, len(chunk))
		copy(chunkCopy, chunk)
		select {
		case chunkedQueue <- chunkCopy:
			return nil
		default:
			// Очередь переполнена, отправляем синхронно
			return sendChunksChunked([][]byte{chunkCopy})
		}
	}

	// Обычная отправка - шифруем здесь
	enc := encrypt(chunk)
	logf("[Send] Encrypted chunk, len=%d\n", len(enc))

	if *usePut {
		u := buildURL(serverURL, false, false)
		req, err := http.NewRequest(http.MethodPut, u, strings.NewReader(enc))
		if err != nil {
			return err
		}
		if overrideHost != "" {
			req.Host = overrideHost
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			logError("[Send] Error sending chunk: %v\n", err)
			return err
		}
		resp.Body.Close()
		logf("[Send] Chunk sent successfully\n")
		return nil
	} else {
		u := buildURL(serverURL, false, false)
		u += fmt.Sprintf("&data=%s", url.QueryEscape(enc))
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		if overrideHost != "" {
			req.Host = overrideHost
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			logError("[Send] Error sending chunk: %v\n", err)
			return err
		}
		resp.Body.Close()
		logf("[Send] Chunk sent successfully\n")
		return nil
	}
}

// hasActiveStreams проверяет, есть ли активные стримы
func hasActiveStreams() bool {
	hasActive := false
	streams.Range(func(key, value interface{}) bool {
		stream := value.(*Stream)
		stream.mu.Lock()
		closed := stream.closed
		stream.mu.Unlock()
		if !closed {
			hasActive = true
			return false // Прерываем итерацию
		}
		return true
	})
	return hasActive
}

func pollLoop() {
	consecutiveNoData := 0                   // Счетчик последовательных NO_DATA ответов
	maxNoDataDelay := 5 * time.Second        // Максимальная задержка при отсутствии данных (увеличено)
	minNoDataDelay := 100 * time.Millisecond // Минимальная задержка

	for {
		// Проверяем, есть ли активные стримы перед отправкой poll
		if !hasActiveStreams() {
			// Нет активных стримов - ждем уведомления о новом стриме
			// Не отправляем poll-запросы вообще, пока не появится активное соединение
			consecutiveNoData = 0 // Сбрасываем счетчик
			select {
			case <-streamNotify:
				// Получили уведомление о новом стриме - продолжаем цикл
				continue
			case <-time.After(10 * time.Second):
				// Периодически проверяем (на всякий случай, если уведомление потерялось)
				continue
			}
		}

		u := buildURL(serverURL, true, false)
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			time.Sleep(1 * time.Millisecond)
			continue
		}
		if overrideHost != "" {
			req.Host = overrideHost
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second) // Увеличена задержка при ошибке сети
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Проверяем статус ответа
		if resp.StatusCode != http.StatusOK {
			logf("[Poll] Server returned status %d: %s\n", resp.StatusCode, resp.Status)
			time.Sleep(2 * time.Second) // Увеличена задержка при ошибке
			consecutiveNoData = 0
			continue
		}

		sbody := string(body)
		if sbody == "NO_DATA" || sbody == "" {
			consecutiveNoData++
			// Адаптивная задержка: увеличиваем при множественных NO_DATA
			delay := time.Duration(*pollInterval) * time.Microsecond
			if consecutiveNoData > 5 {
				// После 5 NO_DATA подряд увеличиваем задержку экспоненциально
				// Экспоненциальная задержка: 100ms, 200ms, 400ms, 800ms, 1.6s, 3.2s, 5s (макс)
				exp := consecutiveNoData - 5
				if exp > 6 {
					exp = 6
				}
				delay = minNoDataDelay * time.Duration(1<<uint(exp))
				if delay > maxNoDataDelay {
					delay = maxNoDataDelay
				}
			}
			time.Sleep(delay)
			continue
		}

		// Есть данные - сбрасываем счетчик
		consecutiveNoData = 0

		// Проверяем, не является ли ответ HTML-страницей с ошибкой
		if strings.HasPrefix(sbody, "<html>") || strings.HasPrefix(sbody, "<!DOCTYPE") {
			logError("[Poll] Received HTML response instead of encrypted data (likely server error): %s\n", sbody[:min(200, len(sbody))])
			time.Sleep(1 * time.Second)
			consecutiveNoData = 0
			continue
		}

		// Есть данные - сбрасываем счетчик NO_DATA
		consecutiveNoData = 0

		if len(sbody) > 0 {
			maxLen := 50
			if len(sbody) < maxLen {
				maxLen = len(sbody)
			}
			logf("[Poll] Received response: len=%d, starts with: %q\n", len(sbody), sbody[:maxLen])
		}

		logf("[Poll] Received response, len=%d\n", len(sbody))
		plain, ok := decrypt(sbody)
		if !ok {
			logError("[Poll] Failed to decrypt response (len=%d, key=%v)\n", len(sbody), aesKey != nil)
			continue
		}
		if len(plain) < 2 {
			logf("[Poll] Plain data too short: %d bytes\n", len(plain))
			continue
		}
		logf("[Poll] Received and decrypted %d bytes of data\n", len(plain))
		logf("[Poll] Received %d bytes of data\n", len(plain))

		// Обрабатываем батч чанков (может быть несколько чанков)
		// Формат: streamID (2) + размер (2) + seq (4) + данные
		offset := 0
		for offset < len(plain) {
			if len(plain[offset:]) < 8 {
				break // Недостаточно данных для заголовка (2+2+4)
			}

			streamID := binary.BigEndian.Uint16(plain[offset : offset+2])
			offset += 2
			chunkSize := int(binary.BigEndian.Uint16(plain[offset : offset+2]))
			offset += 2
			seq := binary.BigEndian.Uint32(plain[offset : offset+4])
			offset += 4

			if len(plain[offset:]) < chunkSize {
				break // Недостаточно данных для чанка
			}

			payload := plain[offset : offset+chunkSize]
			offset += chunkSize

			val, _ := streams.Load(streamID)
			if val == nil {
				logf("[Poll] Stream %d not found, skipping\n", streamID)
				continue
			}
			st := val.(*Stream)

			st.mu.Lock()
			if st.closed {
				st.mu.Unlock()
				continue
			}

			// Логика Reordering (упорядочивания)
			if seq < st.nextDownstreamSeq {
				// Старый пакет или дубликат
				st.mu.Unlock()
				continue
			}

			// Оптимизация: копируем payload только если нужен reordering
			// (есть пропуски в seq или уже есть pending chunks)
			var payloadCopy []byte
			needsCopy := seq > st.nextDownstreamSeq && (st.pendingChunks != nil && len(st.pendingChunks) > 0)
			if needsCopy {
				// Нужен reordering - копируем
				payloadCopy = make([]byte, len(payload))
				copy(payloadCopy, payload)
			} else {
				// Reordering не нужен - используем слайс напрямую
				payloadCopy = payload
			}

			// Сохраняем в буфер
			if st.pendingChunks == nil {
				st.pendingChunks = make(map[uint32][]byte)
			}
			st.pendingChunks[seq] = payloadCopy

			// Обрабатываем доступные последовательные чанки
			for {
				data, ok := st.pendingChunks[st.nextDownstreamSeq]
				if !ok {
					break // Ждем следующий по порядку пакет
				}

				// Удаляем из буфера и увеличиваем ожидаемый seq
				delete(st.pendingChunks, st.nextDownstreamSeq)
				st.nextDownstreamSeq++

				// Если данные пустые - это сигнал закрытия
				if len(data) == 0 {
					st.closed = true
					st.localConn.Close() // Закрываем соединение с браузером
					// streams.Delete(streamID) - удалим позже по таймауту или сразу?
					// Лучше сразу, так как соединение закрыто
					go func(sid uint16) {
						streams.Delete(sid)
					}(streamID)
					logf("[↓] Stream %d: получен сигнал закрытия от сервера (через reordering)\n", streamID)
					break // Стрим закрыт, дальше обрабатывать нечего
				}

				// Пишем данные в локальное соединение
				logf("[↓] Stream %d: writing %d bytes to local\n", streamID, len(data))
				_, err := st.localConn.Write(data)
				if err != nil {
					logError("[Error] Stream %d: write error: %v\n", streamID, err)
					st.closed = true
					go func(sid uint16) {
						streams.Delete(sid)
					}(streamID)
					break // Ошибка записи, стрим закрывается
				}
			}
			st.mu.Unlock()
		}
	}
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 512)

	// Handshake
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 5 {
		return
	}
	conn.Write([]byte{5, 0}) // no auth

	// Request
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 5 || buf[1] != 1 {
		return
	}

	// Парсим адрес
	var addrBytes []byte
	atyp := buf[3]

	switch atyp {
	case 1: // IPv4
		if n < 10 {
			return
		}
		addrBytes = buf[4:10] // 4 bytes IP + 2 bytes port
	case 3: // Domain
		if n < 5 {
			return
		}
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return
		}
		addrBytes = append([]byte{byte(domainLen)}, buf[5:5+domainLen+2]...)
	case 4: // IPv6
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	// Успешный ответ клиенту
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	streamID := nextStreamID()
	if streamID == 0 {
		return
	}
	stream := &Stream{
		localConn: conn,
		seq:       0,                      // Начинаем с seq=0
		sendQueue: make(chan []byte, 100), // Буферизованный канал для асинхронной отправки
	}
	streams.Store(streamID, stream)

	// Уведомляем поллеры о новом активном стриме (неблокирующе)
	select {
	case streamNotify <- struct{}{}:
	default:
		// Канал полон - это нормально, значит поллеры уже уведомлены
	}

	// Запускаем горутину для асинхронной отправки чанков
	go func() {
		for chunk := range stream.sendQueue {
			if err := sendChunk(chunk); err != nil {
				stream.mu.Lock()
				stream.sendErr = err
				stream.mu.Unlock()
				logError("[Error] Stream %d: ошибка отправки: %v\n", streamID, err)
				break
			}
		}
	}()

	// Первый чанк: seq (4) + streamID (2) + ATYP (1) + ADDR+PORT
	// seq=0 означает, что это инициализирующий чанк с адресом
	firstChunk := make([]byte, 4+2+1+len(addrBytes))
	binary.BigEndian.PutUint32(firstChunk[:4], 0) // seq = 0
	binary.BigEndian.PutUint16(firstChunk[4:6], streamID)
	firstChunk[6] = atyp
	copy(firstChunk[7:], addrBytes)

	// Синхронно отправляем первый чанк с retry
	var sendErr error
	for retry := 0; retry < 3; retry++ {
		sendErr = sendChunk(firstChunk)
		if sendErr == nil {
			break
		}
		if retry < 2 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if sendErr != nil {
		logError("[Error] Поток %d: ошибка отправки первого чанка после 3 попыток: %v\n", streamID, sendErr)
		return
	}

	stream.seq = 1 // Следующий seq будет 1

	// Без задержки - sequence numbers гарантируют порядок
	// time.Sleep не нужен

	// Красивый лог
	host := getHostFromAtyp(atyp, addrBytes)
	port := getPortFromAddrBytes(addrBytes)
	logf("[%d] %s:%d\n", streamID, host, port)

	// Upstream: читаем из локального соединения и отправляем на сервер
	readBuf := make([]byte, *chunkSize)
	totalSent := 0

	for {
		// Проверяем ошибку отправки перед чтением
		stream.mu.Lock()
		if stream.sendErr != nil {
			stream.mu.Unlock()
			logf("[Error] Stream %d: ошибка отправки: %v\n", streamID, stream.sendErr)
			break
		}
		stream.mu.Unlock()

		conn.SetReadDeadline(time.Now().Add(time.Duration(*readTimeout) * time.Second))
		n, err := conn.Read(readBuf)
		if err != nil || n == 0 {
			logf("[-] Stream %d: чтение завершено (отправлено %.1f KB)\n", streamID, float64(totalSent)/1024)
			break
		}

		// Формат чанка: seq (4) + streamID (2) + данные
		stream.mu.Lock()
		seq := stream.seq
		stream.seq++
		stream.mu.Unlock()

		chunk := make([]byte, 4+2+n)
		binary.BigEndian.PutUint32(chunk[:4], seq)
		binary.BigEndian.PutUint16(chunk[4:6], streamID)
		copy(chunk[6:], readBuf[:n])

		// Асинхронная отправка через канал (не блокирует чтение)
		select {
		case stream.sendQueue <- chunk:
			totalSent += n
		default:
			// Канал переполнен - ждем немного и пробуем снова
			select {
			case stream.sendQueue <- chunk:
				totalSent += n
			case <-time.After(100 * time.Millisecond):
				// Таймаут - проверяем ошибку
				stream.mu.Lock()
				if stream.sendErr != nil {
					stream.mu.Unlock()
					logf("[Error] Stream %d: ошибка отправки: %v\n", streamID, stream.sendErr)
					break
				}
				stream.mu.Unlock()
				// Пытаемся отправить синхронно как fallback
				if err := sendChunk(chunk); err != nil {
					logError("[Error] Stream %d: ошибка синхронной отправки: %v\n", streamID, err)
					break
				}
				totalSent += n
			}
		}
	}

	// Закрытие стрима: отправляем сигнал закрытия на сервер
	stream.mu.Lock()
	seq := stream.seq
	// НЕ помечаем как closed и НЕ удаляем сразу - данные с сервера могут еще приходить
	stream.mu.Unlock()

	// Чанк закрытия: seq + streamID + пустые данные (означает закрытие)
	closeChunk := make([]byte, 4+2)
	binary.BigEndian.PutUint32(closeChunk[:4], seq)
	binary.BigEndian.PutUint16(closeChunk[4:6], streamID)

	// Закрываем канал отправки, чтобы горутина завершилась
	close(stream.sendQueue)

	// Синхронно отправляем последний чанк закрытия (как в старой версии)
	// Это гарантирует, что сигнал закрытия будет отправлен
	if err := sendChunk(closeChunk); err != nil {
		logError("[Error] Stream %d: ошибка отправки сигнала закрытия: %v\n", streamID, err)
	}

	logf("[-] Stream %d: отправлен сигнал закрытия на сервер\n", streamID)

	// Ждем получения сигнала закрытия от сервера (пустой payload)
	// или таймаут 10 секунд
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			logf("[!] Stream %d: таймаут ожидания закрытия от сервера\n", streamID)
			stream.mu.Lock()
			stream.closed = true
			stream.mu.Unlock()
			streams.Delete(streamID)
			return
		case <-ticker.C:
			val, _ := streams.Load(streamID)
			if val == nil {
				// Стрим уже удален (закрыт сервером)
				return
			}
			st := val.(*Stream)
			st.mu.Lock()
			if st.closed {
				st.mu.Unlock()
				streams.Delete(streamID)
				logf("[-] Stream %d: закрыт сервером\n", streamID)
				return
			}
			st.mu.Unlock()
		}
	}
}

func getHostFromAtyp(atyp byte, addrBytes []byte) string {
	switch atyp {
	case 1:
		return net.IP(addrBytes[:4]).String()
	case 3:
		domainLen := int(addrBytes[0])
		return string(addrBytes[1 : 1+domainLen])
	default:
		return "unknown"
	}
}

func getPortFromAddrBytes(addrBytes []byte) int {
	l := len(addrBytes)
	if l < 2 {
		return 0
	}
	return int(binary.BigEndian.Uint16(addrBytes[l-2 : l]))
}

func main() {
	flag.Parse()

	// Открываем файл для логирования
	var err error
	logFile, err = os.OpenFile("client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Записываем заголовок в лог
	logAlways("=== eGET Client started at %s ===\n", time.Now().Format("2006-01-02 15:04:05"))

	if *server == "" {
		fmt.Println("Использование: ./eget-client -server http://example.com/tunnel [опции]")
		fmt.Println("\nОпции производительности:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("╔═══════════════════════════════════════════════════════╗")
	fmt.Println("║         eGET Client - HTTP Tunnel SOCKS5              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════╝")
	fmt.Printf("Сервер: %s\n", *server)
	fmt.Printf("Сессия: %s\n", *id)
	fmt.Printf("Пользователь: %s\n", *userFlag)
	fmt.Printf("SOCKS5: %s\n", *listen)
	fmt.Println("───────────────────────────────────────────────────────")
	fmt.Printf("Поллеры:      %d\n", *pollers)
	fmt.Printf("Размер чанка:  %d байт\n", *chunkSize)
	fmt.Printf("HTTP timeout:  %d сек\n", *httpTimeout)
	fmt.Printf("Max idle:      %d/%d (total/host)\n", *maxIdleConns, *maxIdleConnsHost)
	fmt.Printf("Poll timeout:  %d сек (для сервера)\n", *pollTimeout)
	fmt.Printf("Max queue:     %d чанков (для сервера)\n", *maxQueue)
	if *usePut {
		fmt.Printf("PUT mode:      enabled\n")
		if *useChunked {
			fmt.Printf("Chunked:       enabled (batch mode)\n")
		}
	}
	fmt.Println("═══════════════════════════════════════════════════════")

	serverURL = *server
	sessionID = *id
	// user = *userFlag // Имя больше не используется для аутентификации

	// Загрузка ключа: флаг приоритетнее переменной окружения
	keyHex := *keyFlag
	if keyHex == "" {
		keyHex = os.Getenv("EGET_KEY")
	}

	if len(keyHex) == 32 {
		var err error
		aesKey, err = hex.DecodeString(keyHex)
		if err != nil || len(aesKey) != 16 {
			logAlways("FATAL: Invalid EGET_KEY (must be 32 hex chars): %v\n", err)
			os.Exit(1)
		}
	} else if keyHex != "" {
		logAlways("FATAL: Invalid EGET_KEY length (must be 32 hex chars for AES-128)\n")
		os.Exit(1)
	}

	if aesKey != nil {
		sum := sha256.Sum256(aesKey)
		user = hex.EncodeToString(sum[:])[:16]
		fmt.Printf("[DEBUG] Computed user hash: %s (from key: %s, key len=%d)\n", user, keyHex, len(aesKey))
	} else {
		fmt.Printf("[DEBUG] No encryption key provided\n")
	}

	overrideHost = *serverHost

	fmt.Print("\nПроверка доступности сервера... ")
	if checkServer() {
		fmt.Println("доступен ✓")
		serverAlive = true
	} else {
		fmt.Println("недоступен ✗")
		fmt.Println("Проверьте URL, сеть или запуск сервера.")
		os.Exit(1)
	}

	// Запускаем несколько поллеров для параллельной обработки (как в старой версии)
	for i := 0; i < *pollers; i++ {
		go pollLoop()
	}
	go healthMonitor()

	// Запускаем chunked sender, если включен chunked transfer
	if *usePut && *useChunked {
		go chunkedSender()
		logAlways("Chunked transfer encoding enabled\n")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logAlways("FATAL: Не удалось запустить SOCKS5: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ SOCKS5 прокси запущен на %s\n\n", *listen)

	// Обработка сигналов для корректного завершения
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nПолучен сигнал завершения, закрываю сессию на сервере...")

		// Отправляем запрос на закрытие сессии
		u := buildURL(serverURL, false, true)
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err == nil {
			if overrideHost != "" {
				req.Host = overrideHost
			}
			httpClient.Do(req)
		}

		fmt.Println("Сессия закрыта. Завершение работы...")
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(conn)
	}
}
