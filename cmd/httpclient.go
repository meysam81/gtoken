package gtoken

import (
	"time"

	"github.com/imroc/req/v3"
)

var (
	HTTPClient = req.C().
		SetCommonRetryCount(3).
		SetCommonRetryBackoffInterval(100*time.Millisecond, 3*time.Second)
)
