package apis

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"ondc-buyer/demo_app/configs"
	"ondc-buyer/demo_app/cryptoUtils"
	"ondc-buyer/demo_app/subscribe"
	"ondc-buyer/demo_app/utils"
	"strings"
)

func InitiateOndcOnApis(r *gin.Engine) {
	r.POST("/on_subscribe", func(c *gin.Context) {
		subscribe.On_subscribe_response(c)
	})

	// Define a route for "/ondc-site-verification.html"
	r.GET("/ondc-site-verification.html", func(c *gin.Context) {
		signedContent, err := cryptoUtils.CreateSignedData(configs.GlobalConfigs.OndcConfigs.RequestId, configs.GlobalConfigs.OndcConfigs.SigningPrivateKey)
		if err != nil {
			c.String(http.StatusInternalServerError, fmt.Sprintf("Error creating signed data: %s", err))
			return
		}

		// Use Gin's HTML rendering
		modifiedHTML := strings.Replace(utils.HtmlFile, "SIGNED_UNIQUE_REQ_ID", signedContent, 1)
		c.Data(200, "text/html; charset=utf-8", []byte(modifiedHTML))
	})
}
