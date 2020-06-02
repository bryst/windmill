package main

import (
	"crypto/ecdsa"
	"github.com/gin-gonic/gin"
	"github.com/healthyorchards/windmill/pkg/auth"
	"github.com/healthyorchards/windmill/pkg/auth/keys"
	"log"
	"net/http"
)

func main() {
	router := gin.New()
	api := router.Group("/api")
	v1 := api.Group("/v1")

	v1.Use(auth.NewBasicMiddleware(func() *ecdsa.PublicKey {
		pub, err := keys.ReadRemotePublicKey("http://localhost:8080/api/v1/public_key")
		if err != nil {
			log.Fatal(err)
		}
		return pub
	}, "API1"))

	admin := v1.Group("/admin")

	admin.GET("", auth.WithScopes(func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"health": "Hello there! You are an Admin"})
	}, "admin super-admin"))

	v1.GET("/hello", auth.WithScopes(func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"health": "Hello there common user!"})
	}, "read:api"))

	if err := router.Run("0.0.0.0:8081"); err != nil {
		log.Fatal(err)
	}
}
