package controllers

import (
	"gopher-vault/internal/initializers"
	"gopher-vault/internal/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// /register
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

// /login

// /logout