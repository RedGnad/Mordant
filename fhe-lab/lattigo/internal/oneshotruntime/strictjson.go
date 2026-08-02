package oneshotruntime

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

func decodeStrictJSON(data []byte, target any) error {
	if len(data) == 0 || target == nil || !utf8.Valid(data) {
		return ErrTransport
	}
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return ErrTransport
	}

	// encoding/json deliberately accepts case-insensitive field aliases. Validate
	// the complete token stream against the exact schema before invoking it.
	schemaDecoder := json.NewDecoder(bytes.NewReader(data))
	schemaDecoder.UseNumber()
	if err := scanTypedJSONValue(schemaDecoder, value.Elem().Type()); err != nil {
		return ErrTransport
	}
	if _, err := schemaDecoder.Token(); err != io.EOF {
		return ErrTransport
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

type exactJSONField struct {
	typeValue reflect.Type
	required  bool
}

func scanTypedJSONValue(decoder *json.Decoder, valueType reflect.Type) error {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	token, err := decoder.Token()
	if err != nil || token == nil { // Explicit null is outside the runtime profile.
		return ErrTransport
	}

	switch valueType.Kind() {
	case reflect.Struct:
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
			return ErrTransport
		}
		fields, err := exactJSONFields(valueType)
		if err != nil {
			return err
		}
		seen := make(map[string]struct{}, len(fields))
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrTransport
			}
			key, ok := keyToken.(string)
			if !ok || !canonicalJSONMemberName(key) {
				return ErrTransport
			}
			field, known := fields[key]
			if !known {
				return ErrTransport
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrTransport
			}
			seen[key] = struct{}{}
			if err := scanTypedJSONValue(decoder, field.typeValue); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrTransport
		}
		for name, field := range fields {
			if _, present := seen[name]; field.required && !present {
				return ErrTransport
			}
		}
		return nil

	case reflect.Slice:
		if valueType.Elem().Kind() == reflect.Uint8 {
			if _, ok := token.(string); !ok {
				return ErrTransport
			}
			return nil
		}
		fallthrough
	case reflect.Array:
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
			return ErrTransport
		}
		for decoder.More() {
			if err := scanTypedJSONValue(decoder, valueType.Elem()); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrTransport
		}
		return nil

	case reflect.String:
		if _, ok := token.(string); !ok {
			return ErrTransport
		}
		return nil
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrTransport
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		if _, ok := token.(json.Number); !ok {
			return ErrTransport
		}
		return nil
	default:
		return ErrTransport
	}
}

func exactJSONFields(structType reflect.Type) (map[string]exactJSONField, error) {
	fields := make(map[string]exactJSONField, structType.NumField())
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		if !canonicalJSONMemberName(name) {
			return nil, ErrTransport
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrTransport
		}
		fields[name] = exactJSONField{typeValue: field.Type, required: field.Tag.Get("required") == "true"}
	}
	return fields, nil
}

// Runtime schema names are deliberately confined to printable ASCII identifiers.
// This rejects Unicode case-fold and confusable aliases after JSON escape decoding.
func canonicalJSONMemberName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= utf8.RuneSelf || !(character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_') {
			return false
		}
	}
	return true
}

func validateRequiredValues(value reflect.Value) error {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ErrTransport
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}
	typeValue := value.Type()
	for index := 0; index < value.NumField(); index++ {
		fieldType := typeValue.Field(index)
		if fieldType.PkgPath != "" || strings.Split(fieldType.Tag.Get("json"), ",")[0] == "-" {
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
