package aqua

import "errors"

type flightVal uint8

const (
	flight0 flightVal = iota + 1
	flight1
	flight2
	flight3
	flight4
	flight5
	flight6
	unknown
)

func (f flightVal) String() string {
	switch f {
	case flight0:
		return "Flight 0"
	case flight1:
		return "Flight 1"
	case flight2:
		return "Flight 2"
	case flight3:
		return "Flight 3"
	case flight4:
		return "Flight 4"
	case flight5:
		return "Flight 5"
	case flight6:
		return "Flight 6"
	default:
		return "Invalid Flight"
	}
}

func (f flightVal) isLastSendFlight() bool {
	return f == flight6
}

func (f flightVal) isLastRecvFlight() bool {
	return f == flight5
}

func (f flightVal) getFlightHandler() (flightHandle, error) {
	switch f {
	case flight0:
		return flight0Handle, nil
	case flight1:
		return flight1Handle, nil
	case flight2:
		return flight2Handle, nil
	case flight3:
		return flight3Handle, nil
	case flight4:
		return flight4Handle, nil
	case flight5:
		return flight5Handle, nil
	case flight6:
		return flight6Handle, nil
	default:
		return nil, errors.New("Invalid Flight")
	}
}

// isClient 根据flgihtVal判断Flight的发送者
func (f flightVal) isClient() bool {
	if f&1 == 1 {
		return true
	} else {
		return false
	}
}
