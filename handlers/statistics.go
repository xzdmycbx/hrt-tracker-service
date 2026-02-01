package handlers

import (
	"net/http"

	"hrt-tracker-service/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type StatisticsHandler struct {
	DB *gorm.DB
}

func NewStatisticsHandler(db *gorm.DB) *StatisticsHandler {
	return &StatisticsHandler{DB: db}
}

// GetSystemStatistics 获取系统统计信息（公开API，每小时更新一次）
func (h *StatisticsHandler) GetSystemStatistics(c *gin.Context) {
	var stats models.SystemStatistics

	// 获取最新的统计记录
	if err := h.DB.First(&stats).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, gin.H{
				"total_users":           0,
				"data_syncs_last_7days": 0,
				"database_size_mb":      0.0,
				"last_updated_at":       nil,
				"message":               "Statistics not yet available",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve statistics",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total_users":           stats.TotalUsers,
		"data_syncs_last_7days": stats.DataSyncsLast7Days,
		"database_size_mb":      stats.DatabaseSizeMB,
		"last_updated_at":       stats.LastUpdatedAt,
	})
}
