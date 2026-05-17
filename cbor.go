package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Minimal CBOR decoder for WebAuthn attestationObject and COSE_Key. It supports
// definite-length integers, byte strings, text strings, arrays and maps.
type cborKind int

const (
	cborInvalid cborKind = iota
	cborInt
	cborBytes
	cborString
	cborArray
	cborMap
)

type cborValue struct {
	kind       cborKind
	intValue   int64
	bytesValue []byte
	strValue   string
	arrayValue []cborValue
	mapValue   map[any]cborValue
}

//nolint:gocognit,cyclop,funlen // This minimal CBOR decoder is deliberately local and explicit for WebAuthn.
func parseCBOR(data []byte) (cborValue, []byte, error) {
	if len(data) == 0 {
		return cborValue{}, nil, io.ErrUnexpectedEOF
	}
	b := data[0]
	major := b >> 5
	ai := b & 0x1f
	n, rest, err := cborReadLen(ai, data[1:])
	if err != nil {
		return cborValue{}, nil, err
	}
	switch major {
	case 0:
		if n > uint64(^uint64(0)>>1) {
			return cborValue{}, nil, fmt.Errorf("integer too large")
		}
		return cborValue{kind: cborInt, intValue: int64(n)}, rest, nil
	case 1:
		if n > uint64(^uint64(0)>>1) {
			return cborValue{}, nil, fmt.Errorf("integer too large")
		}
		return cborValue{kind: cborInt, intValue: -1 - int64(n)}, rest, nil
	case 2:
		if uint64(len(rest)) < n {
			return cborValue{}, nil, io.ErrUnexpectedEOF
		}
		return cborValue{kind: cborBytes, bytesValue: append([]byte{}, rest[:n]...)}, rest[n:], nil
	case 3:
		if uint64(len(rest)) < n {
			return cborValue{}, nil, io.ErrUnexpectedEOF
		}
		return cborValue{kind: cborString, strValue: string(rest[:n])}, rest[n:], nil
	case 4:
		arr := make([]cborValue, 0, n)
		cur := rest
		for i := uint64(0); i < n; i++ {
			v, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			arr = append(arr, v)
			cur = r
		}
		return cborValue{kind: cborArray, arrayValue: arr}, cur, nil
	case 5:
		m := make(map[any]cborValue, n)
		cur := rest
		for i := uint64(0); i < n; i++ {
			k, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			cur = r
			v, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			cur = r
			switch k.kind {
			case cborInt:
				m[k.intValue] = v
			case cborString:
				m[k.strValue] = v
			case cborInvalid, cborBytes, cborArray, cborMap:
				return cborValue{}, nil, fmt.Errorf("unsupported cbor map key")
			default:
				return cborValue{}, nil, fmt.Errorf("unsupported cbor map key")
			}
		}
		return cborValue{kind: cborMap, mapValue: m}, cur, nil
	default:
		return cborValue{}, nil, fmt.Errorf("unsupported cbor major type %d", major)
	}
}

func cborReadLen(ai byte, data []byte) (uint64, []byte, error) {
	switch {
	case ai < 24:
		return uint64(ai), data, nil
	case ai == 24:
		if len(data) < 1 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(data[0]), data[1:], nil
	case ai == 25:
		if len(data) < 2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint16(data[:2])), data[2:], nil
	case ai == 26:
		if len(data) < 4 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint32(data[:4])), data[4:], nil
	case ai == 27:
		if len(data) < 8 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return binary.BigEndian.Uint64(data[:8]), data[8:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported indefinite or reserved cbor length")
	}
}

func cborGetString(m map[any]cborValue, key string) (cborValue, bool) {
	v, ok := m[key]
	return v, ok
}

func cborGetInt(m map[any]cborValue, key int64) (cborValue, bool) {
	v, ok := m[key]
	return v, ok
}
