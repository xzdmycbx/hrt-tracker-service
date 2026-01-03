package main

import (
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/handlers"
	"hrt-tracker-service/middleware"
	"log"
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

	// Start rate limit cleanup goroutine
	go middleware.CleanupRateLimitStore()

	// Setup Gin router
	router := gin.Default()

	// CORS middleware
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Public routes
	public := router.Group("/api")
	{
		// Auth
		public.POST("/auth/register", handlers.Register)
		public.POST("/auth/login", handlers.Login)
		public.POST("/auth/refresh", handlers.RefreshToken)

		// Public share viewing
		public.POST("/shares/:share_id/view", handlers.ViewShare)
	}

	// Protected routes (require authentication)
	protected := router.Group("/api")
	protected.Use(middleware.AuthMiddleware())
	{
		// User management
		protected.POST("/user/security-password", handlers.SetSecurityPassword)
		protected.PUT("/user/security-password", handlers.UpdateSecurityPassword)
		protected.GET("/user/security-password/status", handlers.GetSecurityPasswordStatus)

		// User data with rate limiting
		protected.POST("/user/data",
			middleware.RateLimitMiddleware(10, 1*time.Minute, 5*time.Minute),
			handlers.GetUserData)
		protected.PUT("/user/data",
			middleware.RateLimitMiddleware(20, 1*time.Minute, 5*time.Minute),
			handlers.UpdateUserData)

		// Session management with rate limiting
		protected.GET("/auth/sessions",
			middleware.RateLimitMiddleware(30, 1*time.Minute, 5*time.Minute),
			handlers.GetSessions)
		protected.DELETE("/auth/sessions/:session_id",
			middleware.RateLimitMiddleware(10, 5*time.Minute, 15*time.Minute),
			handlers.RevokeSession)
		protected.DELETE("/auth/sessions",
			middleware.RateLimitMiddleware(5, 5*time.Minute, 15*time.Minute),
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
