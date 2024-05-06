package httpClient

import (
	"context"
	"encoding/json"
	"net/http"
)

// APIRequest : request object
type APIRequest struct {
	BaseURL             string
	Action              string
	Headers             map[string]string
	RequestURLParams    map[string]string
	IsAuthRequired      bool
	IsQueryParamsExists bool
	IsURLParamsExists   bool
	RequestQueryParams  map[string]string
	Authentication      RestAPIAuth
	TimeOut             int
	HttpHeaders         http.Header
	IsFormdataExists    bool
	Formdata            map[string]string
	ReqCtx              context.Context
	IsProxySet          bool
	ProxyAddress        string
}

func (a *APIRequest) String() string {
	b, _ := json.Marshal(&a)
	return string(b)
}

// APIResponse : API response object
type APIResponse struct {
	Response string
	Status   int
	Err      error
}

// RestAPIAuth is authentication for API
type RestAPIAuth struct {
	Username string
	Password string
}
