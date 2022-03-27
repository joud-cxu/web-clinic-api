package routes

import (
	"github.com/Shaieb524/web-clinic.git/controllers"

	"github.com/gofiber/fiber/v2"
)

func AppointmentRoutes(app *fiber.App) {
	app.Post("/appointments/book-appointment", controllers.BookAppointmentSlot)
	app.Post("/appointments/cancel-appointment", controllers.CancelAppointmentSlot)
	app.Post("/appointments/view-appointment", controllers.ViewAppointmentDetails)
}
