package services

import (
	"log"
	"os"
	"time"

	"hrt-tracker-service/models"
	"gorm.io/gorm"
)

var globalStatsService *StatisticsService

type StatisticsService struct {
	db     *gorm.DB
	dbPath string
	ticker *time.Ticker
	done   chan bool
}

// SetGlobalStatsService sets the global statistics service instance
func SetGlobalStatsService(service *StatisticsService) {
	globalStatsService = service
}

// GetGlobalStatsService returns the global statistics service instance
func GetGlobalStatsService() *StatisticsService {
	return globalStatsService
}

func NewStatisticsService(db *gorm.DB, dbPath string) *StatisticsService {
	return &StatisticsService{
		db:     db,
		dbPath: dbPath,
		done:   make(chan bool),
	}
}

// Start 启动统计服务，每小时更新一次
func (s *StatisticsService) Start() {
	log.Println("Statistics service started - updating every hour")

	// 立即更新一次
	s.UpdateStatistics()

	// 每小时更新一次
	s.ticker = time.NewTicker(1 * time.Hour)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.UpdateStatistics()
			case <-s.done:
				return
			}
		}
	}()
}

// Stop 停止统计服务
func (s *StatisticsService) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true
	log.Println("Statistics service stopped")
}

// UpdateStatistics 更新统计数据
func (s *StatisticsService) UpdateStatistics() {
	log.Println("Updating system statistics...")

	// 1. 获取总用户数
	var totalUsers int64
	if err := s.db.Model(&models.User{}).Count(&totalUsers).Error; err != nil {
		log.Printf("Error counting users: %v", err)
		return
	}

	// 2. 获取七天内的数据同步次数
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	var syncCount int64
	if err := s.db.Model(&models.DataSyncCounter{}).
		Where("timestamp >= ?", sevenDaysAgo).
		Count(&syncCount).Error; err != nil {
		log.Printf("Error counting data syncs: %v", err)
		return
	}

	// 3. 获取数据库文件大小（MB）
	var dbSizeMB float64
	if fileInfo, err := os.Stat(s.dbPath); err == nil {
		dbSizeMB = float64(fileInfo.Size()) / (1024 * 1024)
	} else {
		log.Printf("Error getting database file size: %v", err)
	}

	// 4. 更新或创建统计记录（只保留一条记录）
	var stats models.SystemStatistics
	result := s.db.First(&stats)

	if result.Error == gorm.ErrRecordNotFound {
		// 创建新记录
		stats = models.SystemStatistics{
			TotalUsers:         int(totalUsers),
			DataSyncsLast7Days: syncCount,
			DatabaseSizeMB:     dbSizeMB,
			LastUpdatedAt:      time.Now(),
		}
		if err := s.db.Create(&stats).Error; err != nil {
			log.Printf("Error creating statistics: %v", err)
			return
		}
	} else if result.Error == nil {
		// 更新现有记录
		if err := s.db.Model(&stats).Updates(map[string]interface{}{
			"total_users":           int(totalUsers),
			"data_syncs_last7_days": syncCount,
			"database_size_mb":      dbSizeMB,
			"last_updated_at":       time.Now(),
		}).Error; err != nil {
			log.Printf("Error updating statistics: %v", err)
			return
		}
	} else {
		log.Printf("Error querying statistics: %v", result.Error)
		return
	}

	// 5. 清理超过7天的同步计数记录（节省空间）
	if err := s.db.Where("timestamp < ?", sevenDaysAgo).Delete(&models.DataSyncCounter{}).Error; err != nil {
		log.Printf("Error cleaning old sync counters: %v", err)
	}

	log.Printf("Statistics updated: Users=%d, Syncs(7d)=%d, DB Size=%.2f MB",
		totalUsers, syncCount, dbSizeMB)
}

// RecordDataSync 记录一次数据同步（拉取）
func (s *StatisticsService) RecordDataSync() error {
	counter := models.DataSyncCounter{
		Timestamp: time.Now(),
	}
	return s.db.Create(&counter).Error
}
