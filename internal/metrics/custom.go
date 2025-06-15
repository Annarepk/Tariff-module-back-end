package metrics

import (
	"sync"
	"time"
)

type timeSlot struct {
	Timestamp time.Time
	Count     int
}

var (
	mu            sync.Mutex
	allTimestamps []timeSlot
)

// Зарегистрировать один запрос
func RecordRequest() {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	allTimestamps = append(allTimestamps, timeSlot{
		Timestamp: now,
		Count:     1,
	})

	// Удалим всё, что старше суток
	cutoff := now.Add(-24 * time.Hour)
	i := 0
	for ; i < len(allTimestamps); i++ {
		if allTimestamps[i].Timestamp.After(cutoff) {
			break
		}
	}
	allTimestamps = allTimestamps[i:]
}

// Подсчитать количество за X времени
func CountSince(d time.Duration) int {
	mu.Lock()
	defer mu.Unlock()

	cutoff := time.Now().Add(-d)
	sum := 0
	for _, slot := range allTimestamps {
		if slot.Timestamp.After(cutoff) {
			sum += slot.Count
		}
	}
	return sum
}
