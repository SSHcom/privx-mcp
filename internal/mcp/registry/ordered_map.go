package registry

import (
	"bytes"
	"encoding/json"
)

// OrderedMap is a string-keyed map that preserves insertion order when
// marshalled to JSON. Unlike a plain map[string]any, whose keys
// encoding/json emits in sorted order, an OrderedMap emits keys in the
// order they were added. Use it for tool InputSchemas where the displayed
// field order matters (e.g. grouping related inputs ahead of pagination).
type OrderedMap struct {
	keys   []string
	values map[string]any
}

// NewOrderedMap returns an empty OrderedMap ready for use.
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{values: make(map[string]any)}
}

// Set stores value under key, appending key to the ordered key list on
// first insertion. Re-setting an existing key keeps its original position.
func (m *OrderedMap) Set(key string, value any) *OrderedMap {
	if _, exists := m.values[key]; !exists {
		m.keys = append(m.keys, key)
	}

	m.values[key] = value

	return m
}

// ForEach invokes fn for each key/value pair in insertion order. It is the
// read-side counterpart to Set and lets callers compose schemas by copying
// entries from one OrderedMap into another (e.g. extending a shared property
// set with tool-specific leading fields).
func (m *OrderedMap) ForEach(fn func(key string, value any)) {
	for _, k := range m.keys {
		fn(k, m.values[k])
	}
}

// MarshalJSON emits the object with keys in insertion order.
func (m *OrderedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')

	for i, k := range m.keys {
		if i > 0 {
			buf.WriteByte(',')
		}

		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}

		buf.Write(keyBytes)
		buf.WriteByte(':')

		valBytes, err := json.Marshal(m.values[k])
		if err != nil {
			return nil, err
		}

		buf.Write(valBytes)
	}

	buf.WriteByte('}')

	return buf.Bytes(), nil
}
