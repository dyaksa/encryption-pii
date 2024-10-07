package datatype

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON defined JSON data type, need to implements driver.Valuer, sql.Scanner interface
type JSON json.RawMessage

// Value return json value, implement driver.Valuer interface
func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

// Scan scan value into Jsonb, implements sql.Scanner interface
func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = JSON("null")
		return nil
	}
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		if len(v) > 0 {
			bytes = make([]byte, len(v))
			copy(bytes, v)
		}
	case string:
		bytes = []byte(v)
	default:
		return errors.New(fmt.Sprint("Failed to unmarshal JSONB value:", value))
	}

	result := json.RawMessage(bytes)
	*j = JSON(result)
	return nil
}

// MarshalJSON to output non base64 encoded []byte
func (j JSON) MarshalJSON() ([]byte, error) {
	return json.RawMessage(j).MarshalJSON()
}

func (j JSON) Unmarshal(v any) (err error) {
	b, err := j.MarshalJSON()
	err = json.Unmarshal(b, &v)
	return
}

// UnmarshalJSON to deserialize []byte
func (j *JSON) UnmarshalJSON(b []byte) error {
	result := json.RawMessage{}
	err := result.UnmarshalJSON(b)
	*j = JSON(result)
	return err
}

func (j JSON) String() string {
	return string(j)
}
