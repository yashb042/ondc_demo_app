package utils

import (
	"time"
)

func GetFirstValue(n interface{}, _ error) interface{} {
	return n
}

func GetTimestamp() string {
	currentTime := time.Now().UTC()
	layout := "2006-01-02T15:04:05"
	formattedTime := currentTime.Format(layout)
	formattedTime = formattedTime + ".001Z"
	return formattedTime
}
