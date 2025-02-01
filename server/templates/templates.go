package templates

import (
	"html/template"
	"log"
	"net/http"
)

type LoginPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RegisterPage struct {
	BAlertUser bool
	AlertMsg   string
}

type RestrictedPage struct {
	CsrfSecret    string
	SecretMessage string
}

var templates = template.Must(
	template.ParseFiles("./server/templates/templateFiles/login.tmp",
		"./server/templates/templateFiles/register.tmp",
		"./server/templates/templateFiles/restricted.tmp",
	),
)

func RenderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".tmp", p)
	if err != nil {
		log.Printf("Tempalte error here: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
