package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Shaieb524/web-clinic.git/configs"
	"github.com/Shaieb524/web-clinic.git/customsturctures"
	"github.com/Shaieb524/web-clinic.git/helpers"
	"github.com/Shaieb524/web-clinic.git/models"
	"github.com/Shaieb524/web-clinic.git/responses"
	"github.com/go-redis/redis"
	"github.com/microsoft/ApplicationInsights-Go/appinsights"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	// "github.com/go-playground/validator/v10"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

// var validate = validator.New()

func Ping(c *gin.Context) {
	fmt.Println("SS : ", c.Request.Header.Get("CorrelationID"))
	c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"message": "pong"}})
}

func RegisterUser(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var data map[string]string

	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "couldn't parse request!", Data: map[string]interface{}{"error": err}})
		return
	}

	var newUser models.User
	// TODO use the validator library to validate required fields
	// if validationErr := validate.Struct(&newUser); validationErr != nil {
	// 	c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "couldn't validate request!", Data: map[string]interface{}{"error": validationErr.Error()}})
	// 	return
	// }

	//encypt user's password before saving to db
	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 12)

	newUser = models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
		Role:     data["role"],
	}

	// if user is a doctor then initialize a schedule
	if data["role"] == "doctor" {
		ds := models.DoctorSchedule(helpers.GenerateWeekDoctorSchedule("_id"))
		newUser.Schedule = ds
		newUser.Available = true
	} else if data["role"] == "patient" {

	}

	result, err := userCollection.InsertOne(ctx, newUser)

	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "failed to reigster user!", Data: map[string]interface{}{"error": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: map[string]interface{}{"user": result}})
}

func Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var data map[string]string

	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, responses.UserResponse{Status: http.StatusBadRequest, Message: "failed", Data: map[string]interface{}{"data": err.Error()}})
		return
	}

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": data["email"]}).Decode(&user)

	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "failed", Data: map[string]interface{}{"message": "Invalid Credentials"}})
		return
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		c.JSON(http.StatusUnauthorized, responses.UserResponse{Status: http.StatusUnauthorized, Message: "failed", Data: map[string]interface{}{"message": "Invalid Credentials"}})
		return
	}

	pair, err := generateTokenPair(user.Email)

	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"message": "Login failed!"}})
		return
	}

	c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"access_token": pair.Access_Token}})
}

func generateTokenPair(userEmail string) (customsturctures.TokenPair, error) {

	var tPair customsturctures.TokenPair

	authClaim := customsturctures.AuthClaimers{
		StandardClaims: jwt.StandardClaims{
			Subject:   userEmail,
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
		Email: userEmail,
	}

	// create access token
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, authClaim)

	atoken, err := claims.SignedString([]byte(configs.EnvTokenSecretKey()))
	if err != nil {
		return tPair, err
	}

	// create refresh token
	rtclaims := jwt.NewWithClaims(jwt.SigningMethodHS256, authClaim)

	rtoken, err := rtclaims.SignedString([]byte(configs.EnvRefreshTokenSecretKey()))
	if err != nil {
		return tPair, err
	}

	tPair = customsturctures.TokenPair{Access_Token: atoken, Refresh_Token: rtoken}

	return tPair, nil
}

func CheckTrace(c *gin.Context) {

	// define dummy data to set/get to/from redis
	type testItem struct {
		ReqId string `json:"reqid"`
	}

	// ping redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	pong, err := redisClient.Ping().Result()
	fmt.Println(pong, err)

	requestId := c.Request.Header.Get("CorrelationID")
	jsonItem, err := json.Marshal(testItem{ReqId: requestId})

	if err != nil {
		fmt.Println(err)
	}

	err = redisClient.Set("id1", jsonItem, 0).Err()
	if err != nil {
		fmt.Println(err)
	}
	val, err := redisClient.Get("id1").Result()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("get redis val : ", val)

	// initialize appinsights client
	client := appinsights.NewTelemetryClient(configs.AzureInstrumentation())

	// track redis call as dependecy trace
	dependency := appinsights.NewRemoteDependencyTelemetry("Redis cache", "Redis", "<target>", true /* success */)

	// // The result code is typically an error code or response status code
	// dependency.ResultCode = "OK"

	// // Id's can be used for correlation if the remote end is also logging
	// // telemetry through application insights.
	// dependency.Id = "<request id>"

	// // Data may contain the exact URL hit or SQL statements
	// dependency.Data = "MGET <args>"

	// // The duration can be set directly:
	// dependency.Duration = time.Minute

	// // Properties and measurements may be set.
	// dependency.Properties["shard-instance"] = "<name>"
	// dependency.Measurements["data received"] = float64(len(response.data))

	// Submit the telemetry
	client.Track(dependency)

	// resp, err := http.Get("http://localhost:8888/call-node")
	// if err != nil {
	// 	fmt.Println("err : ", err)
	// }

	// responseData, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// // dependency := appinsights.NewRemoteDependencyTelemetry("Redis cache", "Redis", "<target>", true /* success */)

	// client := appinsights.NewTelemetryClient(configs.AzureInstrumentation())

	// // track request
	// startTime := time.Now()
	// duration := time.Now().Sub(startTime)
	// requestTrace := appinsights.NewRequestTelemetry("GET", "http://localhost:6000/check-tracee", duration, "200")
	// requestTrace.Timestamp = time.Now()
	// client.Track(requestTrace)

	c.JSON(http.StatusOK, responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"message": "string(responseData)"}})

}

// type handler struct{}

// This is the api to refresh tokens
// Most of the code is taken from the jwt-go package's sample codes
// https://godoc.org/github.com/dgrijalva/jwt-go#example-Parse--Hmac
// func RefreshToken(c echo.Context) {
// 	type tokenReqBody struct {
// 		RefreshToken string `json:"refresh_token"`
// 	}
// 	tokenReq := tokenReqBody{}
// 	c.Bind(&tokenReq)

// 	// Parse takes the token string and a function for looking up the key.
// 	// The latter is especially useful if you use multiple keys for your application.
// 	// The standard is to use 'kid' in the head of the token to identify
// 	// which key to use, but the parsed token (head and claims) is provided
// 	// to the callback, providing flexibility.
// 	token, err := jwt.Parse(tokenReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
// 		// Don't forget to validate the alg is what you expect:
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 		}

// 		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
// 		return []byte("secret"), nil
// 	})

// 	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
// 		// Get the user record from database or
// 		// run through your business logic to verify if the user can log in
// 		if int(claims["sub"].(float64)) == 1 {

// 			newTokenPair, err := generateTokenPair("joud@gmail.com")
// 			if err != nil {
// 				return err
// 			}

// 			return c.JSON(http.StatusOK, newTokenPair)
// 		}

// 		return echo.ErrUnauthorized
// 	}

// 	return err
// }
