package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func EnvMongoURI() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("MONGO_URI")
}

func EnvSecretKey() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("SECRET_KEY")
}

func EnvPort() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("API_PORT")
}
