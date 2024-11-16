package mderive

import (
	"strconv"
	"strings"
)

func DerivePrivateKey(key *Key, path string) (*Key, error) {
	points := strings.Split(path, "/")
	if len(points) <= 0 || points[0] != "m" {
		return nil, ErrDerivationPathInvalid
	}

	points = points[1:]
	var keyPoint = key
	for _, point := range points {
		flag := false

		code := uint32(0x80000000)
		if point[len(point)-1:] == "'" {
			point = point[:len(point)-1]
			flag = true
		}

		pointNum, err := strconv.ParseInt(point, 10, 32)
		if err != nil {
			return nil, ErrDerivationPathInvalid
		}

		if flag {
			code = code | uint32(pointNum)
		} else {
			code = uint32(pointNum)
		}

		keyPoint, err = keyPoint.NewChild(code)
		if err != nil {
			return nil, err
		}
	}

	return keyPoint, nil
}
