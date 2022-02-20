package logging

import (
	"errors"
)

var (
	RemoteAddr         = errors.New("RemoteAddr error")
	ConnectionNotFound = errors.New("connection not found")
	IPProtocol         = errors.New("IP protocol number not recognized")
)
