package middleware

import (
	"gopher-vault/api/initializers"
	"gopher-vault/internal/models"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func RequireAuth(c *gin.Context) {
	// Get the cookie of request
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error" : "Authorization token not found.",
		})
		return
	}

	// Ensure the SECRET environment variable is correctly set
	jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        log.Println("JWT_SECRET environment variable is not set.")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
    }

	// Deconde / validate token
	token, err := jwt.Parse(tokenString, func(token * jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			if err != nil {
				log.Printf("Error retrieving token: %v", err)
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error" : "Invalid authorization token.",
		})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID := claims["user_id"].(string)

		// Find the user with token sub
		var user models.User
		initializers.DB.First(&user, "id = ?", userID)

		if user.ID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error" : "User not found.",
			})
			return
		}

		// Attach to request
		c.Set("user", user)
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error" : "Invalid authorization token.",
		})
		return
	}
	c.Next()
}