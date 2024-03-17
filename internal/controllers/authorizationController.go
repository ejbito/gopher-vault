package controllers

import (
	"gopher-vault/api/initializers"
	"gopher-vault/internal/models"
	"gopher-vault/middleware"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Register
func Register(c *gin.Context) {
	// Get email / password from req body
	var body struct {
		Email string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body.",
		})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error" : "Failed to hash password",
		})
		return
	}

	// Create user
	user := models.User{Email: body.Email, Password: string(hash)}

	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error" : "Failed to create user.",
		})
	}

	// Response
	c.JSON(http.StatusOK, gin.H{})
}

// Login
func Login(c *gin.Context) {
	// Get email / password from req body
	var body struct {
		Email string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body.",
		})
		return
	}

	// Look up request user
	var user models.User

	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error" : "Invalid email or password.",
		})
		return
	}

	// Compare sent in password with saved user password hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error" : "Invalid email or password",
		})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	// Ensure the SECRET environment is correctly set
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error" : "Failed to create token.",
		})
		return
	}

	// Sign and get the complete encoded token as a string using secret
	tokenString, err := token.SignedString([]byte(jwtSecret))

	if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to create token.",
        })
        return
    }

	// Respond with JWT token
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 360 * 24, "", "", false, true) // false as its local server

	c.JSON(http.StatusOK, gin.H{
		"token" : tokenString,
	})
}

// Logout
func Logout(c *gin.Context) {
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error" : "Authorization token not found.",
		})
		return
	}

	// Ensure the SECRET environment is correctly set
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Server configuration error.",
        })
        return
    }

	// Extract claims to get expiration time
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error){
		return []byte(jwtSecret), nil
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error" : "Token has expired.",
		})
		return
	}

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        exp := int64(claims["exp"].(float64))

		// Calculate remaining time until token expiration
        ttl := time.Until(time.Unix(exp, 0))

		// Add the token to the blacklist with the TTL
		middleware.Blacklist.Set(tokenString, true, ttl)
	}
}