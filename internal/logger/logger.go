package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(verbose bool, quiet bool) (*zap.Logger, error) {
	level := zapcore.WarnLevel
	if verbose {
		level = zapcore.DebugLevel
	}
	if quiet {
		level = zapcore.ErrorLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.Encoding = "console"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build()
}
