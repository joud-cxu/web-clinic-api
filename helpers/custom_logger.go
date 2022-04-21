package helpers

import (
	"encoding/json"

	"go.uber.org/zap"
)

func InitCustomLogger() *zap.Logger {

	rawJSON := []byte(`{
		"level": "debug",
		"encoding": "json",
		"outputPaths": ["stdout", "logs/debug.log"], 
		"errorOutputPaths": ["stderr", "logs/debug.log"], 
		"encoderConfig": {
		  "messageKey": "message",
		  "levelKey": "level",
		  "levelEncoder": "lowercase"
		}
	}`)

	var cfg zap.Config
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		panic(err)
	}
	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	return logger
}

var CustomLogger *zap.Logger = InitCustomLogger()
