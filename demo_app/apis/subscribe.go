package apis

import (
	"github.com/gin-gonic/gin"
	"ondc-buyer/demo_app/subscribe"
)

func InitiateSubscribeApi(r *gin.Engine) {
	r.POST("/ondc_subscribe", func(c *gin.Context) {
		subscribe.SubscribeToONDCNetwork(c)
	})
}
