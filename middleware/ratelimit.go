package middleware

import (
	"fmt"
	"hrt-tracker-service/utils"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateLimitEntry struct {
	count     int
	resetTime time.Time
	locked    bool
	lockUntil time.Time
}

var (
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitMutex sync.RWMutex
)

// getRealIP extracts the real IP from request headers
func getRealIP(c *gin.Context) string {
	// Priority: X-Forwarded-For (first IP) > X-Real-IP > ClientIP
	forwarded := c.GetHeader("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	realIP := c.GetHeader("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return c.ClientIP()
}

// getRateLimitKey generates a unique key for rate limiting based on user ID, IP, method and endpoint
func getRateLimitKey(userID uint, ip string, method string, endpoint string) string {
	return fmt.Sprintf("%d:%s:%s:%s", userID, ip, method, endpoint)
}

// RateLimitMiddleware creates a rate limiting middleware
// maxRequests: maximum requests allowed
// window: time window duration
// lockDuration: how long to lock after exceeding limit
func RateLimitMiddleware(maxRequests int, window time.Duration, lockDuration time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserID(c)
		if userID == 0 {
			// If no user ID (public endpoint), skip rate limiting
			c.Next()
			return
		}

		ip := getRealIP(c)
		method := c.Request.Method
		endpoint := c.FullPath()
		key := getRateLimitKey(userID, ip, method, endpoint)

		rateLimitMutex.Lock()
		defer rateLimitMutex.Unlock()

		now := time.Now()
		entry, exists := rateLimitStore[key]

		if !exists {
			// First request, create new entry
			rateLimitStore[key] = &rateLimitEntry{
				count:     1,
				resetTime: now.Add(window),
				locked:    false,
			}
			c.Next()
			return
		}

		// Check if locked
		if entry.locked {
			if now.Before(entry.lockUntil) {
				utils.TooManyRequestsResponse(c, fmt.Sprintf("Too many requests. Locked until %s", entry.lockUntil.Format(time.RFC3339)))
				c.Abort()
				return
			}
			// Lock expired, reset
			entry.locked = false
			entry.count = 1
			entry.resetTime = now.Add(window)
			c.Next()
			return
		}

		// Check if window expired
		if now.After(entry.resetTime) {
			// Reset counter
			entry.count = 1
			entry.resetTime = now.Add(window)
			c.Next()
			return
		}

		// Increment counter
		entry.count++

		// Check if exceeded limit
		if entry.count > maxRequests {
			entry.locked = true
			entry.lockUntil = now.Add(lockDuration)
			utils.TooManyRequestsResponse(c, fmt.Sprintf("Too many requests. Locked for %s", lockDuration))
			c.Abort()
			return
		}

		c.Next()
	}
}

// Cleanup old entries periodically (call this in a goroutine)
func CleanupRateLimitStore() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		rateLimitMutex.Lock()
		now := time.Now()
		for key, entry := range rateLimitStore {
			// Remove entries that are no longer locked and past reset time
			if !entry.locked && now.After(entry.resetTime.Add(1 * time.Hour)) {
				delete(rateLimitStore, key)
			}
			// Remove unlocked entries past lock time
			if entry.locked && now.After(entry.lockUntil.Add(1 * time.Hour)) {
				delete(rateLimitStore, key)
			}
		}
		rateLimitMutex.Unlock()
	}
}
