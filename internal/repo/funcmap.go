package repo

import (
	"html/template"
	"strings"

	"github.com/Masterminds/sprig/v3"
)

var t *template.Template

func funcMap() template.FuncMap {
	funcMap := sprig.FuncMap()
	funcMap["include"] = func(name string, data interface{}) (string, error) {
		var buf strings.Builder
		err := t.ExecuteTemplate(&buf, name, data)
		return buf.String(), err
	}
	return funcMap
}
