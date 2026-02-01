package models

import "time"

// SystemStatistics 系统统计信息（每小时更新一次缓存）
type SystemStatistics struct {
	ID                 uint      `gorm:"primaryKey"`
	TotalUsers         int       `gorm:"not null;default:0"`                // 总用户数
	DataSyncsLast7Days int64     `gorm:"not null;default:0"`                // 七天内数据同步次数
	DatabaseSizeMB     float64   `gorm:"not null;default:0"`                // 数据库大小（MB）
	LastUpdatedAt      time.Time `gorm:"not null"`                          // 最后更新时间
	CreatedAt          time.Time `gorm:"autoCreateTime"`
	UpdatedAt          time.Time `gorm:"autoUpdateTime"`
}

// DataSyncCounter 数据同步计数器（轻量级，只记录拉取次数）
type DataSyncCounter struct {
	ID        uint      `gorm:"primaryKey"`
	Timestamp time.Time `gorm:"not null;index"` // 同步时间（用于统计七天内的数据）
	CreatedAt time.Time `gorm:"autoCreateTime"`
}
