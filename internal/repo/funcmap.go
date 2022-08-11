package repo

import (
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

var t *template.Template

func funcMap() template.FuncMap {
	funcMap := sprig.TxtFuncMap()
	funcMap["include"] = func(name string, data interface{}) (string, error) {
		var buf strings.Builder
		err := t.ExecuteTemplate(&buf, name, data)
		return buf.String(), err
	}
	return funcMap
}
