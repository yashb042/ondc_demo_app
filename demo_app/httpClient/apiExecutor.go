package httpClient

import (
	"context"
	"github.com/go-resty/resty/v2"
	"net/http"
	"time"

	"go.elastic.co/apm/module/apmhttp/v2"
)

func POST(ctx context.Context, apirequest APIRequest, requestBody []byte, loggingDisabled ...bool) APIResponse {
	resp := new(APIResponse)
	some := apmhttp.WrapClient(http.DefaultClient)
	client := resty.NewWithClient(some)
	client.SetTimeout(time.Duration(apirequest.TimeOut) * time.Millisecond)
	if apirequest.IsQueryParamsExists {
		client.SetQueryParams(apirequest.RequestQueryParams)
	}

	if apirequest.IsAuthRequired {
		client.SetBasicAuth(apirequest.Authentication.Username, apirequest.Authentication.Password)
	}
	if apirequest.IsURLParamsExists {
		client.SetPathParams(apirequest.RequestURLParams)
	}
	endpoint := apirequest.BaseURL + apirequest.Action

	//Set context is setting the context as null, try it out later when enable trace is to be used
	response, err := client.R().EnableTrace().SetHeaders(apirequest.Headers).SetBody(requestBody).Post(endpoint)
	resp.Err = err
	resp.Response = response.String()
	resp.Status = response.StatusCode()

	return *resp
}
