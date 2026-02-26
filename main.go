package main

import (
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/handlers"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/services"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	config.LoadConfig()

	// Initialize database
	if err := database.InitDB(config.AppConfig.DBPath); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Initialize and start statistics service
	statsService := services.NewStatisticsService(database.GetDB(), config.AppConfig.DBPath)
	services.SetGlobalStatsService(statsService)
	statsService.Start()

	// Start rate limit cleanup goroutine
	go middleware.CleanupRateLimitStore()

	// Setup Gin router
	// Use gin.New() (no built-in middleware) so we can register CORS first.
	// CORS MUST be the first middleware: if it comes after Recovery, a panic
	// response would be written by Recovery before CORS sets its headers.
	router := gin.New()

	// Configure trusted proxies for accurate client IP detection
	// In production, set this to your actual proxy IPs (e.g., Cloudflare, nginx)
	// For development, trust all proxies (not recommended for production)
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatal("Failed to set trusted proxies:", err)
	}

	// ── 1. CORS (first — always runs, even on panics) ─────────────────────────
	allowedOrigins := buildAllowedOriginsSet(config.AppConfig.CORSAllowedOrigins)
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if allowedOrigins["*"] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" && allowedOrigins[origin] {
			// Echo the specific allowed origin and tell caches it varies by Origin
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Vary", "Origin")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// ── 2. Logger & Recovery (after CORS so error responses also carry CORS headers)
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Health check endpoint (支持 GET 和 HEAD 请求，用于 Docker healthcheck)
	healthHandler := func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	}
	router.GET("/health", healthHandler)
	router.HEAD("/health", healthHandler)

	// Statistics handler
	statsHandler := handlers.NewStatisticsHandler(database.GetDB())

	// Public routes
	public := router.Group("/api")
	{
		// Public statistics endpoint (no authentication required)
		public.GET("/statistics", statsHandler.GetSystemStatistics)
		// Auth endpoints with rate limiting to prevent brute force
		public.POST("/auth/register",
			middleware.PublicRateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.Register)
		public.POST("/auth/login",
			middleware.PublicRateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.Login)
		public.POST("/auth/refresh",
			middleware.PublicRateLimitMiddleware(50, 5*time.Minute, 15*time.Minute),
			handlers.RefreshToken)

		// OIDC / OAuth2 endpoints (public — user not yet authenticated)
		public.GET("/auth/oidc/config",
			middleware.PublicRateLimitMiddleware(150, 1*time.Minute, 5*time.Minute),
			handlers.OIDCGetConfig)
		public.GET("/auth/oidc/authorize",
			middleware.PublicRateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.OIDCGetAuthorizeURL)
		public.POST("/auth/oidc/callback",
			middleware.PublicRateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.OIDCCallback)

		// Public share viewing with rate limiting to prevent password brute force
		public.POST("/shares/:share_id/view",
			middleware.PublicRateLimitMiddleware(50, 5*time.Minute, 15*time.Minute),
			handlers.ViewShare)

		// Public avatar access with rate limiting (防爬虫)
		public.GET("/avatars/:username",
			middleware.PublicRateLimitMiddleware(150, 1*time.Minute, 10*time.Minute),
			handlers.GetAvatar)
	}

	// Protected routes (require authentication)
	protected := router.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		// User management
		protected.POST("/user/security-password", handlers.SetSecurityPassword)
		protected.PUT("/user/security-password", handlers.UpdateSecurityPassword)
		protected.GET("/user/security-password/status", handlers.GetSecurityPasswordStatus)

		// Login password management
		protected.PUT("/user/password",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.ChangePassword)
		// Set initial login password (for OIDC-only accounts)
		protected.POST("/user/password",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.SetLoginPassword)
		// Remove login password (requires OIDC to be bound)
		protected.DELETE("/user/password",
			middleware.RateLimitMiddleware(10, 5*time.Minute, 15*time.Minute),
			handlers.RemoveLoginPassword)

		// OIDC management (authenticated user)
		protected.GET("/auth/oidc/bind/authorize",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.OIDCGetBindAuthorizeURL)
		protected.POST("/auth/oidc/bind/callback",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.OIDCBindCallback)
		protected.GET("/auth/oidc/bind/status",
			middleware.RateLimitMiddleware(150, 1*time.Minute, 5*time.Minute),
			handlers.OIDCBindStatus)

		// Avatar management with rate limiting
		protected.POST("/user/avatar",
			middleware.RateLimitMiddleware(15, 10*time.Minute, 30*time.Minute),
			handlers.UploadAvatar)
		protected.DELETE("/user/avatar",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.DeleteAvatar)

		// User data with rate limiting
		protected.POST("/user/data",
			middleware.RateLimitMiddleware(200, 1*time.Minute, 5*time.Minute),
			handlers.GetUserData)
		protected.PUT("/user/data",
			middleware.RateLimitMiddleware(100, 1*time.Minute, 5*time.Minute),
			handlers.UpdateUserData)

		// Session management with rate limiting
		protected.GET("/auth/sessions",
			middleware.RateLimitMiddleware(150, 1*time.Minute, 5*time.Minute),
			handlers.GetSessions)
		protected.POST("/auth/logout", handlers.Logout)
		protected.DELETE("/auth/sessions/:session_id",
			middleware.RateLimitMiddleware(50, 5*time.Minute, 15*time.Minute),
			handlers.RevokeSession)
		protected.DELETE("/auth/sessions",
			middleware.RateLimitMiddleware(25, 5*time.Minute, 15*time.Minute),
			handlers.RevokeAllOtherSessions)

		// Share management
		protected.POST("/shares", handlers.CreateShare)
		protected.GET("/shares", handlers.GetMyShares)
		protected.DELETE("/shares/:share_id", handlers.DeleteShare)
		protected.PUT("/shares/:share_id/password", handlers.UpdateSharePassword)
		protected.PUT("/shares/:share_id/lock", handlers.UpdateShareLock)

		// Authorization management
		protected.POST("/authorizations", handlers.GrantAuthorization)
		protected.DELETE("/authorizations/:viewer_username", handlers.RevokeAuthorization)
		protected.GET("/authorizations/granted", handlers.GetMyAuthorizations)
		protected.GET("/authorizations/received", handlers.GetAuthorizedOwners)
		protected.POST("/authorizations/view", handlers.ViewAuthorizedData)
	}

	// Start server
	log.Printf("Server starting on port %s", config.AppConfig.Port)
	if err := router.Run(":" + config.AppConfig.Port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// buildAllowedOriginsSet parses CORS_ALLOWED_ORIGINS into a fast-lookup set.
// Supports "*" (wildcard) or comma-separated origin URLs.
func buildAllowedOriginsSet(raw string) map[string]bool {
	set := map[string]bool{}
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			set[o] = true
		}
	}
	if len(set) == 0 {
		set["*"] = true // safe default
	}
	return set
}
