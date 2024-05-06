package subscribe

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"ondc-buyer/demo_app/configs"
	"ondc-buyer/demo_app/cryptoUtils"
)

type OnSubscribeResponse struct {
	SubscriberId string `json:"subscriber_id"`
	Challenge    string `json:"challenge"`
}

func On_subscribe_response(c *gin.Context) {
	var onSubscribeResponse OnSubscribeResponse

	if err := c.BindJSON(&onSubscribeResponse); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	fmt.Print("onSubscribeResponse: %+v\n", onSubscribeResponse)

	decryptedText, err := cryptoUtils.Decrypt(configs.GlobalConfigs.OndcConfigs.PrivateKeyCrypto,
		configs.GlobalConfigs.OndcConfigs.OndcEncryptionPublicKey,
		onSubscribeResponse.Challenge)

	if err != nil {
		print(err)
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	fmt.Println("decryptedText: %+v\n", decryptedText)
	c.JSON(200, gin.H{"answer": decryptedText})
}
