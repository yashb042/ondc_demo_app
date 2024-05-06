package ondcRequest

type OndcAckRequest struct {
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
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
