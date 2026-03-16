package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// requestLogger is a middleware that logs HTTP requests
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Process request
		next.ServeHTTP(ww, r)

		// Log request details
		duration := time.Since(start)
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Int("status", ww.Status()).
			Int("bytes", ww.BytesWritten()).
			Dur("duration", duration).
			Str("request_id", middleware.GetReqID(r.Context())).
			Msg("HTTP request")
	})
}

// rateLimiter implements a simple token bucket rate limiter
func rateLimiter(requestsPerMinute int) func(http.Handler) http.Handler {
	type client struct {
		tokens     int
		lastRefill time.Time
		mu         sync.Mutex
	}

	clients := make(map[string]*client)
	clientsMu := sync.RWMutex{}

	// Cleanup old clients periodically
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			clientsMu.Lock()
			now := time.Now()
			for ip, c := range clients {
				c.mu.Lock()
				if now.Sub(c.lastRefill) > 10*time.Minute {
					delete(clients, ip)
				}
				c.mu.Unlock()
			}
			clientsMu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := r.RemoteAddr

			// Get or create client
			clientsMu.RLock()
			c, exists := clients[ip]
			clientsMu.RUnlock()

			if !exists {
				c = &client{
					tokens:     requestsPerMinute,
					lastRefill: time.Now(),
				}
				clientsMu.Lock()
				clients[ip] = c
				clientsMu.Unlock()
			}

			// Check and consume token
			c.mu.Lock()
			now := time.Now()

			// Refill tokens based on time elapsed
			elapsed := now.Sub(c.lastRefill)
			if elapsed >= time.Minute {
				c.tokens = requestsPerMinute
				c.lastRefill = now
			}

			// Check if tokens available
			if c.tokens <= 0 {
				c.mu.Unlock()
				log.Warn().
					Str("ip", ip).
					Str("path", r.URL.Path).
					Msg("Rate limit exceeded")
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Consume token
			c.tokens--
			c.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
