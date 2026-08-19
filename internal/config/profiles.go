package config

import "fmt"

// LevelProfile описывает параметры нагрузки для уровня детальности аудита.
type LevelProfile struct {
	Level           int
	Name            string
	Workers         int
	RateLimitPerSec int
	TimeoutSeconds  int
	RecursionDepth  int
}

// levelProfiles — фиксированная таблица уровней 1-5.
var levelProfiles = map[int]LevelProfile{
	1: {Level: 1, Name: "stealth", Workers: 2, RateLimitPerSec: 1, TimeoutSeconds: 30, RecursionDepth: 1},
	2: {Level: 2, Name: "polite", Workers: 5, RateLimitPerSec: 5, TimeoutSeconds: 20, RecursionDepth: 2},
	3: {Level: 3, Name: "normal", Workers: 10, RateLimitPerSec: 10, TimeoutSeconds: 15, RecursionDepth: 3},
	4: {Level: 4, Name: "aggressive", Workers: 25, RateLimitPerSec: 50, TimeoutSeconds: 10, RecursionDepth: 4},
	5: {Level: 5, Name: "thorough", Workers: 50, RateLimitPerSec: 100, TimeoutSeconds: 5, RecursionDepth: 5},
}

// ProfileForLevel возвращает профиль для уровня 1-5. Уровень 0 трактуется как 3 (normal).
func ProfileForLevel(level int) (LevelProfile, error) {
	if level == 0 {
		level = 3
	}
	profile, ok := levelProfiles[level]
	if !ok {
		return LevelProfile{}, fmt.Errorf("invalid level %d: must be between 1 and 5", level)
	}
	return profile, nil
}

// ApplyProfile применяет параметры профиля к HTTP-конфигурации.
// Значения из профиля переопределяют timeout и rate limit, но не трогают
// явно заданные прокси и User-Agent.
func (c *Config) ApplyProfile(profile LevelProfile) {
	if c == nil {
		return
	}
	if profile.TimeoutSeconds > 0 {
		c.HTTP.TimeoutSeconds = profile.TimeoutSeconds
	}
	if profile.RateLimitPerSec > 0 {
		c.HTTP.RateLimitPerSec = profile.RateLimitPerSec
	}
	c.HTTP.Normalize()
}
