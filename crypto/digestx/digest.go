package digestx

import (
	"hash"
	"io"
)

func digest(h hash.Hash, datas ...[]byte) ([]byte, error) {
	for _, data := range datas {
		_, err := h.Write(data)
		if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

func digestIO(h hash.Hash, r io.Reader) ([]byte, error) {
	_, err := io.Copy(h, r)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
