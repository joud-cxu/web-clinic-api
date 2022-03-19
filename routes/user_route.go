package routes

import (
	"github.com/Shaieb524/web-clinic.git/controllers"

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	app.Post("/user", controllers.CreateUser)
	app.Post("/user/register", controllers.RegisterUser)
	app.Post("/user/login", controllers.Login)
	app.Get("/user/:userId", controllers.GetAUser)
	app.Get("/users", controllers.GetAllUsers)
}
