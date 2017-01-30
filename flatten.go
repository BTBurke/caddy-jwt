// Flatten makes flat, one-dimensional maps from arbitrarily nested ones.
//
// Map keys turn into compound
// names, like `a.b.1.c` (dotted style) or `a[b][1][c]` (Rails style).  It takes input as either JSON strings or
// Go structures.  It (only) knows how to traverse JSON types: maps, slices and scalars.
//
// Or Go maps directly.
//
//	t := map[string]interface{}{
//		"a": "b",
//		"c": map[string]interface{}{
//			"d": "e",
//			"f": "g",
//		},
//		"z": 1.4567,
//	}
//
//	flat, err := Flatten(nested, "", RailsStyle)
//
//	// output:
//	// map[string]interface{}{
//	//	"a":    "b",
//	//	"c[d]": "e",
//	//	"c[f]": "g",
//	//	"z":    1.4567,
//	// }
//
package jwt

import "errors"

// The presentation style of keys.
type SeparatorStyle int

const (
	_ SeparatorStyle = iota

	// Separate nested key components with dots, e.g. "a.b.1.c.d"
	DotStyle

	// Separate ala Rails, e.g. "a[b][c][1][d]"
	RailsStyle
)

// Nested input must be a map or slice
var NotValidInputError = errors.New("Not a valid input: map or slice")

// Flatten generates a flat map from a nested one.  The original may include values of type map, slice and scalar,
// but not struct.  Keys in the flat map will be a compound of descending map keys and slice iterations.
// The presentation of keys is set by style.  A prefix is joined to each key.
func Flatten(nested map[string]interface{}, prefix string, style SeparatorStyle) (map[string]interface{}, error) {
	flatmap := make(map[string]interface{})

	err := flatten(true, flatmap, nested, prefix, style)
	if err != nil {
		return nil, err
	}

	return flatmap, nil
}

func flatten(top bool, flatMap map[string]interface{}, nested interface{}, prefix string, style SeparatorStyle) error {
	assign := func(newKey string, v interface{}) error {
		switch v.(type) {
		case map[string]interface{}:
			if err := flatten(false, flatMap, v, newKey, style); err != nil {
				return err
			}
		default:
			flatMap[newKey] = v
		}

		return nil
	}

	switch nested.(type) {
	case map[string]interface{}:
		for k, v := range nested.(map[string]interface{}) {
			newKey := enkey(top, prefix, k, style)
			assign(newKey, v)
		}
	default:
		return NotValidInputError
	}

	return nil
}

func enkey(top bool, prefix, subkey string, style SeparatorStyle) string {
	key := prefix

	if top {
		key += subkey
	} else {
		switch style {
		case DotStyle:
			key += "." + subkey
		case RailsStyle:
			key += "[" + subkey + "]"
		}
	}

	return key
}
