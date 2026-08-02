package oneshotruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
)

func decodeStrictJSON(data []byte, target any) error {
	if len(data) == 0 || target == nil || rejectDuplicateJSONKeys(data) != nil {
		return ErrTransport
	}
	var fields map[string]json.RawMessage
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return ErrTransport
	}
	if value.Elem().Kind() == reflect.Struct {
		if err := json.Unmarshal(data, &fields); err != nil {
			return ErrTransport
		}
		if err := validateRequiredJSONFields(value.Elem().Type(), fields); err != nil {
			return ErrTransport
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrTransport
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrTransport
	}
	if err := validateRequiredValues(value.Elem()); err != nil {
		return ErrTransport
	}
	return nil
}

func decodeCanonicalPayload(data []byte, target any) error {
	if decodeStrictJSON(data, target) != nil {
		return ErrTransport
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrTransport
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrTransport
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrTransport
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrTransport
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrTransport
			}
			folded := strings.ToLower(key)
			if _, duplicate := seen[folded]; duplicate {
				return ErrTransport
			}
			seen[folded] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrTransport
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrTransport
		}
	default:
		return ErrTransport
	}
	return nil
}

func validateRequiredJSONFields(structType reflect.Type, fields map[string]json.RawMessage) error {
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			name = field.Name
		}
		raw, ok := fields[name]
		if field.Tag.Get("required") == "true" && (!ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))) {
			return ErrTransport
		}
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		if err := validateNestedRequiredJSON(field.Type, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateNestedRequiredJSON(valueType reflect.Type, raw json.RawMessage) error {
	switch valueType.Kind() {
	case reflect.Struct:
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) != nil {
			return ErrTransport
		}
		return validateRequiredJSONFields(valueType, nested)
	case reflect.Slice, reflect.Array:
		element := valueType.Elem()
		if element.Kind() != reflect.Struct {
			return nil
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrTransport
		}
		for _, value := range values {
			if err := validateNestedRequiredJSON(element, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRequiredValues(value reflect.Value) error {
	if value.Kind() != reflect.Struct {
		return nil
	}
	typeValue := value.Type()
	for index := 0; index < value.NumField(); index++ {
		fieldType := typeValue.Field(index)
		if fieldType.PkgPath != "" || fieldType.Tag.Get("required") != "true" || fieldType.Tag.Get("allowzero") == "true" {
			continue
		}
		field := value.Field(index)
		if field.Kind() == reflect.Struct {
			if err := validateRequiredValues(field); err != nil {
				return err
			}
		}
		if (field.Kind() == reflect.Slice || field.Kind() == reflect.Array) && field.Type().Elem().Kind() == reflect.Struct {
			for element := 0; element < field.Len(); element++ {
				if err := validateRequiredValues(field.Index(element)); err != nil {
					return err
				}
			}
		}
		if fieldType.Tag.Get("required") != "true" || fieldType.Tag.Get("allowzero") == "true" {
			continue
		}
		switch field.Kind() {
		case reflect.String, reflect.Array, reflect.Slice, reflect.Map:
			if field.Len() == 0 || field.IsZero() {
				return ErrTransport
			}
		case reflect.Bool:
			if !field.Bool() {
				return ErrTransport
			}
		default:
			if field.IsZero() {
				return ErrTransport
			}
		}
	}
	return nil
}
