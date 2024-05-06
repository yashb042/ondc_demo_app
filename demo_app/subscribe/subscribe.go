package subscribe

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	jsonIterator "github.com/json-iterator/go"
	"net/http"
	"ondc-buyer/demo_app/configs"
	executor "ondc-buyer/demo_app/httpClient"
	"ondc-buyer/demo_app/models/ondcResponse"
	"ondc-buyer/demo_app/utils"
	"strconv"
)

func SubscribeToONDCNetwork(c *gin.Context) {

	subscribeRequest := map[string]interface{}{
		"context": map[string]interface{}{
			"operation": map[string]interface{}{
				"ops_no": 1,
			},
		},
		"message": map[string]interface{}{
			"entity": map[string]interface{}{
				"gst": map[string]interface{}{
					"legal_entity_name": configs.GlobalConfigs.OndcConfigs.GstLegalEntityName,
					"business_address":  configs.GlobalConfigs.OndcConfigs.GstBusinessAddress,
					"city_code":         []string{configs.GlobalConfigs.OndcConfigs.EntityGstCityCode},
					"gst_no":            configs.GlobalConfigs.OndcConfigs.GstNo,
				},
				"pan": map[string]interface{}{
					"name_as_per_pan":       configs.GlobalConfigs.OndcConfigs.NameAsPerPan,
					"pan_no":                configs.GlobalConfigs.OndcConfigs.PanNo,
					"date_of_incorporation": configs.GlobalConfigs.OndcConfigs.PanDateOfIncorporation,
				},
				"name_of_authorised_signatory":    configs.GlobalConfigs.OndcConfigs.NameOfAuthorisedSignatory,
				"address_of_authorised_signatory": configs.GlobalConfigs.OndcConfigs.AddressOfAuthorisedSignatory,
				"email_id":                        configs.GlobalConfigs.OndcConfigs.EmailId,
				"mobile_no":                       utils.GetFirstValue(strconv.Atoi(configs.GlobalConfigs.OndcConfigs.MobileNo)).(int),
				"country":                         "IND",
				"subscriber_id":                   configs.GlobalConfigs.OndcConfigs.SubscriberId,
				"unique_key_id":                   configs.GlobalConfigs.OndcConfigs.SubscribeUniqueId,
				"callback_url":                    "/",
				"key_pair": map[string]interface{}{
					"signing_public_key":    configs.GlobalConfigs.OndcConfigs.SigningPublicKey,
					"encryption_public_key": configs.GlobalConfigs.OndcConfigs.PublicKeyCrypto,
					"valid_from":            configs.GlobalConfigs.OndcConfigs.ValidFrom,
					"valid_until":           configs.GlobalConfigs.OndcConfigs.ValidUntil,
				},
			},
			"network_participant": []map[string]interface{}{
				{
					"subscriber_url": configs.GlobalConfigs.OndcConfigs.BuyerAppUri,
					"domain":         configs.GlobalConfigs.OndcConfigs.NetworkParticipantDomain,
					"type":           configs.GlobalConfigs.OndcConfigs.NetworkParticipantType,
					"msn":            false,
					"city_code":      []string{"*"},
				},
			},
			"timestamp":  utils.GetTimestamp(),
			"request_id": configs.GlobalConfigs.OndcConfigs.RequestId,
		},
	}

	subscribeRequestJSON, err := json.MarshalIndent(subscribeRequest, "", "   ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	var req executor.APIRequest
	req.BaseURL = configs.GlobalConfigs.OndcConfigs.RegistryUrl + "/subscribe"
	print("Subscribe Request : ", string(subscribeRequestJSON))
	print("Subscribe Request URL : ", req.BaseURL)
	apiResp := executor.POST(c.Request.Context(), req, subscribeRequestJSON)

	var ondcAckResponse ondcResponse.OndcAckResponse
	if err := jsonIterator.Unmarshal([]byte(apiResp.Response), &ondcAckResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	if ondcAckResponse.Message.Ack.Status != "ACK" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Subscribe request failed", "message": ondcAckResponse.Error.Message})
		return
	}

	fmt.Print("Subscribe Response : ", ondcAckResponse)

	c.JSON(http.StatusOK, gin.H{"message": "Subscribe request sent successfully"})
}
