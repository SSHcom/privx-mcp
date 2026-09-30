package common

import "strings"

// DeletePaths removes the named paths from root in place.
// A path is dot-separated. A segment ending in [] walks each object in that array.
// Missing segments and non-object array entries are ignored.
func DeletePaths(root map[string]any, paths ...string) {
	if root == nil {
		return
	}

	for _, path := range paths {
		if path == "" {
			continue
		}

		deletePath(root, strings.Split(path, "."))
	}
}

func deletePath(node map[string]any, segments []string) {
	if len(segments) == 0 || node == nil {
		return
	}

	seg := segments[0]
	if strings.HasSuffix(seg, "[]") {
		key := strings.TrimSuffix(seg, "[]")

		items, ok := node[key].([]any)
		if !ok {
			return
		}

		rest := segments[1:]

		for _, item := range items {
			child, ok := item.(map[string]any)
			if !ok {
				continue
			}

			deletePath(child, rest)
		}

		return
	}

	if len(segments) == 1 {
		delete(node, seg)
		return
	}

	child, ok := node[seg].(map[string]any)
	if !ok {
		return
	}

	deletePath(child, segments[1:])
}

// DropNamedAttributes removes objects from the attributes array at arrayPath
// whose key field equals name. arrayPath is dot-separated object keys.
// Missing paths are ignored. Other entries stay.
func DropNamedAttributes(root map[string]any, arrayPath, name string) {
	if root == nil || arrayPath == "" || name == "" {
		return
	}

	parent := root

	key := arrayPath
	if i := strings.LastIndex(arrayPath, "."); i >= 0 {
		parent = objectAt(root, arrayPath[:i])
		key = arrayPath[i+1:]
	}

	if parent == nil {
		return
	}

	items, ok := parent[key].([]any)
	if !ok {
		return
	}

	kept := make([]any, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if ok && m["key"] == name {
			continue
		}

		kept = append(kept, item)
	}

	parent[key] = kept
}

func objectAt(root map[string]any, path string) map[string]any {
	node := root
	for _, seg := range strings.Split(path, ".") {
		next, ok := node[seg].(map[string]any)
		if !ok {
			return nil
		}

		node = next
	}

	return node
}
