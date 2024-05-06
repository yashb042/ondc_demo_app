package ondcResponse

type OndcAckResponse struct {
	Message message   `json:"message"`
	Error   OndcError `json:"error"`
}

type ack struct {
	Status string `json:"status"`
}
type message struct {
	Ack ack `json:"ack"`
}

type OndcError struct {
	Type        string `json:"type"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Description string `json:"description"`
}

func GenerateOndcSuccessResponse() OndcAckResponse {
	ondcAckResponse := OndcAckResponse{
		Message: message{
			Ack: ack{
				Status: "ACK",
			},
		},
	}
	return ondcAckResponse
}

func GenerateOndcFailureResponse(description string) OndcAckResponse {
	ondcAckResponse := OndcAckResponse{
		Message: message{
			Ack: ack{
				Status: "NACK",
			},
		},
		Error: OndcError{
			Message:     "Something went wrong",
			Description: description,
		},
	}
	return ondcAckResponse
}
