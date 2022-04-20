package routes

import (
	"github.com/Shaieb524/web-clinic.git/controllers"

	"github.com/gin-gonic/gin"
)

func UnauthRoutes(router *gin.Engine) {
	router.GET("/ping", controllers.Ping)
	router.POST("/register", controllers.RegisterUser)
	router.POST("/login", controllers.Login)
	router.GET("/check-trace", controllers.CheckTrace)
	// router.POST("/refresh-token", controllers.)
}
