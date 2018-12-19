package api

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
)

var titleValidator = regexp.MustCompile("^[a-zA-Z0-9/-]+$")

func checkTitleValidator(title string) bool {
	return titleValidator.MatchString(title)

}

func loadTemplates(nameTamplate string) (status int, err error) {
	log.Println("log: loadTemplates -> " + nameTamplate)
	if _, err := os.Stat(path.Join("web", "templates", nameTamplate+".html")); os.IsNotExist(err) {
		// file not found
		log.Println("log: loadTemplates -> template not found")
		return 404, err
	}
	templates[nameTamplate], err = template.New(nameTamplate).ParseFiles(path.Join("web", "templates", "layout.html"), path.Join("web", "templates", nameTamplate+".html"))
	log.Println("log: loadTemplates -> template exist")
	return 200, err
}

func renderTemplate(w http.ResponseWriter, r *http.Request, tmpl string, p *page) {
	//log.Println("log: renderTemplate -> "+tmpl)
	if !checkTitleValidator(tmpl) {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	if _, err := templates[tmpl]; !err {
		//log.Println("log: renderTemplate -> err1=false")
		if status, err := loadTemplates(tmpl); err != nil {
			log.Println("log: renderTemplate - error")
			log.Println(err.Error())
			errorHandler(w, r, status)
			return
		}
	} //else { log.Println("log: renderTemplate -> err1=true") }
	if err := templates[tmpl].ExecuteTemplate(w, "layout", p); err != nil {
		log.Println("log: renderTemplate - error")
		log.Println(err.Error())
		errorHandler(w, r, http.StatusInternalServerError)
	}
}
