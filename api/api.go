package api

import (
	"bufio"
	//"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
)

type Config struct {
	NameFile            string
	PublicPath          string
	PublicPathJS        http.FileSystem
	PublicPathCSS       http.FileSystem
	PublicPathTemplates http.FileSystem
}

type user struct {
	Name     string
	Auth     bool
	FileKeys string
}

type key struct {
	Id             string
	Text           string
	ExpirationDate string // Timestamp time.Time -> Timestamp.Format("2006-01-02 15:04:05")
	LastUsed       string
	IsBlosed       string
}

type Page struct {
	Title string
	Body  template.HTML //[]byte
	Auth  bool
	Keys  []key
}

type ClaimsJWT struct {
	Name string `json: "name"`
	jwt.StandardClaims
}

/*
type StandardClaims struct {
    Audience  string `json:"aud,omitempty"`	 	имя клиента для которого токен выпущен.
    ExpiresAt int64  `json:"exp,omitempty"`		срок действия токена.
    Id        string `json:"jti,omitempty"`		уникальный идентификатор токен (нужен, чтобы нельзя был «выпустить» токен второй раз)
    IssuedAt  int64  `json:"iat,omitempty"`		время выдачи токена.
    Issuer    string `json:"iss,omitempty"` 	адрес или имя удостоверяющего центра.
    NotBefore int64  `json:"nbf,omitempty"`		время, начиная с которого может быть использован (не раньше чем).
    Subject   string `json:"sub,omitempty"`		идентификатор пользователя. Уникальный в рамках удостоверяющего центра, как минимум.
}
*/
var tokenAuth *jwtauth.JWTAuth

var u user

var templates = make(map[string]*template.Template)

func init() {
	tokenAuth = jwtauth.New("HS512", []byte("secret"), nil)
}

func Start(cfg Config, listener net.Listener) {

	info, err := os.Stat(path.Join(cfg.PublicPath, cfg.NameFile))
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Файл данных не существует")
			return
		}
	}
	if info.IsDir() {
		log.Println("Указан не файл, а папка")
		return
	}

	u.Create()
	u.setFileKeys(path.Join(cfg.PublicPath, cfg.NameFile))
	r := chi.NewRouter()
	// routers:
	// routers: protected
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth)) // Seek, verify and validate JWT tokens
		r.Use(jwtauth.Authenticator)       // можно переопределить этот метод проверки

		r.Route("/keys", func(rKeys chi.Router) {
			rKeys.Handle("/", keysHandler())
			rKeys.Get("/key/add", keyAddHandler)
			rKeys.Get("/key/{id}/delete", keyDeleteHandler)
		})
	})

	// routers: public
	r.Group(func(r chi.Router) {
		r.Route("/login", func(r chi.Router) {
			r.Post("/", authHandler()) // POST
			r.Get("/", loginHandler)   // GET
		})
		r.Get("/logout", logoutHandler)
		// ways static data
		r.Handle("/css/*", http.StripPrefix("/css/", http.FileServer(cfg.PublicPathCSS)))
		r.Handle("/js/*", http.StripPrefix("/js/", http.FileServer(cfg.PublicPathJS)))
		r.Handle("/templates/*", http.StripPrefix("/templates/", http.FileServer(cfg.PublicPathTemplates)))

		r.Handle("/", indexHandler())
		r.NotFound(error404Handler) // назначаем обработчик, если запрошенный url не существует
	})
	// templates: base
	templates["index"] = template.Must(template.ParseFiles(path.Join(cfg.PublicPath, "templates", "layout.html"), path.Join(cfg.PublicPath, "templates", "index.html")))
	templates["error"] = template.Must(template.ParseFiles(path.Join("web", "templates", "layout.html"), path.Join("web", "templates", "error.html")))
	// server: settings
	server := &http.Server{
		Handler:        r,
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		MaxHeaderBytes: 1 << 16}
	// server: run
	go server.Serve(listener)
}

//********** Routes: api **********************************************************************************************************************************************

func keysHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		keys, err := loadKeys(u.getFileKeys())
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}
		p := Page{Title: "keys", Keys: keys, Auth: u.getAuth()}
		renderTemplate(w, r, "keys", &p)
	})
}

func keyAddHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("keyAddHandler")
	err := keyAdd()
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	// redirect to URL
	http.Redirect(w, r, "/keys", 303)
	return
}

func keyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("keyDeleteHandler")
	idKey, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		log.Println("Error delete key: %v", err)
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	var k key
	err = k.delete(idKey)
	if err != nil {
		log.Println("Error delete key: %v", err)
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	// redirect to URL
	http.Redirect(w, r, "/keys", 303)
	return
}

func loadKeys(fileKeys string) ([]key, error) {
	file, err := os.Open(fileKeys)
	if err != nil {
		log.Println("Error opening file: %v", err)
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	keys := make([]key, 0)

	var k key
	//k.Create("0","","","","")
	var line string
	var cols []string
	for scanner.Scan() {
		line = scanner.Text()
		cols = strings.Split(line, "|")
		if len(cols) > 0 {
			k.Id = cols[0] //strconv.Atoi(cols[0])
			k.Text = cols[1]
			k.ExpirationDate = cols[2]
			k.LastUsed = cols[3]
			k.IsBlosed = cols[4]
			keys = append(keys, k)
		}
		if err = scanner.Err(); err != nil {
			break
		}
	}
	if err != nil {
		log.Println("Error reading file: %v", err)
		return nil, err
	}

	return keys, nil
}

func (k *key) Create(id string, text, expirationDate, lastUsed, isBlosed string) {
	k.Id = id
	k.Text = text
	k.ExpirationDate = expirationDate
	k.LastUsed = lastUsed
	k.IsBlosed = isBlosed
}

func keyAdd() error {
	file, err := os.Open(u.getFileKeys())
	if err != nil {
		log.Println("Error opening file: %v", err)
		return err
	}
	scanner := bufio.NewScanner(file)
	col := 1
	for scanner.Scan() {
		col++
		if err = scanner.Err(); err != nil {
			break
		}
	}
	file.Close()
	file, err = os.OpenFile(u.getFileKeys(), os.O_APPEND|os.O_WRONLY, 0666)
	defer file.Close()
	if err != nil {
		log.Println("Error opening file: %v", err)
		return err
	}
	var rec string
	rec = strconv.Itoa(col)
	rec += "|" + "key" + strconv.Itoa(col)
	t := time.Now()
	rec += "|" + t.Format("2006-01-02 15:04:05")
	rec += "|" + t.Format("2006-01-02 15:04:05")
	rec += "|false"

	log.Println("keyAdd: ", rec)

	if _, err := file.WriteString("\n" + rec); err != nil {
		log.Println("Error writing file:", err)
		return err
	}
	return nil
}

func (k *key) delete(id int) error {
	file, err := os.Open(u.getFileKeys())
	if err != nil {
		log.Println("Error opening file: %v", err)
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var line string
	var cols []string
	number := 0
	numLine := 0
	for scanner.Scan() {
		line = scanner.Text()
		numLine++
		cols = strings.Split(line, "|")
		number, err = strconv.Atoi(cols[0])
		if number == id {
			break
		}
		if err = scanner.Err(); err != nil {
			break
		}
	}
	if err != nil {
		log.Println("Error reading file: %v", err)
		return err
	}

	fileread, err := ioutil.ReadFile(u.getFileKeys())
	if err != nil {
		log.Println("Error opening file: %v", err)
		return err
	}
	lines := strings.Split(string(fileread), "\n")
	lineAfter := strings.Join(lines[0:(numLine-1)], "\n")
	lineBefore := strings.Join(lines[numLine:len(lines)], "\n")
	if len(lineBefore) > 0 {
		lineBefore = "\n" + lineBefore
	}
	return ioutil.WriteFile(u.getFileKeys(), []byte(lineAfter+lineBefore), 0666)

}

//********** Routes: default **********************************************************************************************************************************************

func indexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("indexHandler")
		p := Page{Title: "Home", Body: template.HTML("<p>Home Page</p>"), Auth: u.getAuth()}
		log.Printf("%+v", p)
		//renderTemplate(w, r, "index", &p)
		renderTemplate(w, r, "index", &p)
	})
}

//********** Routes: auth **********************************************************************************************************************************************

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("loginHandler")
	p := Page{Title: "Login", Body: template.HTML("<p>Login Page</p>")}
	renderTemplate(w, r, "login", &p)
}

func authHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("authHandler")
		login := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if login == "admin" && password == "password" {
			u.setAuth(true)
			// создание и запись данных о пользователе в сессию/БД/cookie
			token, err := createTokenJWT(login)
			if err != nil {
				log.Println("Error creating JWT token: ", err)
				errorHandler(w, r, http.StatusInternalServerError)
				return
			}
			//log.Println("JWT token: ", token)
			// cookie
			jwtCookie := &http.Cookie{}
			jwtCookie.Name = "jwt"
			jwtCookie.Value = token
			jwtCookie.Path = "/"
			jwtCookie.Expires = time.Now().Add(time.Hour * 12)
			http.SetCookie(w, jwtCookie)
			//jwtCookie := http.Cookie{Name: "jwt", Value: token, HttpOnly: true, Path: "/", MaxAge: 0}
			//http.SetCookie(w, &jwtCookie)
			// redirect to URL
			http.Redirect(w, r, "/keys", 303)
			return
		}
		p := Page{Title: "Login", Body: template.HTML("<b>User not found!<b>")}
		renderTemplate(w, r, "login", &p)
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("logoutHandler")
	u.setAuth(false)
	jwtCookie := http.Cookie{Name: "jwt", Value: "", HttpOnly: false, Path: "/", MaxAge: -1, Expires: time.Unix(0, 0)}
	http.SetCookie(w, &jwtCookie)
	// redirect to URL
	http.Redirect(w, r, "/", 303)
	return
}

func createTokenJWT(login string) (string, error) {
	claims := ClaimsJWT{
		"testName",
		jwt.StandardClaims{
			Id:        login,                                //уникальный идентификатор токен (нужен, чтобы нельзя было «выпустить» токен второй раз)
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(), //срок действия токена
			/*
				Audience  string `json:"aud,omitempty"`	 	имя клиента для которого токен выпущен.
				ExpiresAt int64  `json:"exp,omitempty"`		срок действия токена.
				Id        string `json:"jti,omitempty"`		уникальный идентификатор токен (нужен, чтобы нельзя был «выпустить» токен второй раз)
				IssuedAt  int64  `json:"iat,omitempty"`		время выдачи токена.
				Issuer    string `json:"iss,omitempty"` 	адрес или имя удостоверяющего центра.
				NotBefore int64  `json:"nbf,omitempty"`		время, начиная с которого может быть использован (не раньше чем).
				Subject   string `json:"sub,omitempty"`		идентификатор пользователя. Уникальный в рамках удостоверяющего центра, как минимум.
			*/
		},
	}
	_, tokenEncodeString, err := tokenAuth.Encode(claims)
	if err != nil {
		return "", err
	}
	return tokenEncodeString, nil
}

//********** Routes: error **********************************************************************************************************************************************

func error404Handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(404)
	log.Println("log: error404Handler")
	log.Println(r.URL.Path)
	err := templates["error"].ExecuteTemplate(w, "layout", map[string]interface{}{"Error": http.StatusText(404), "Status": 404})
	if err != nil {
		log.Println("log: error404Handler->error: " + err.Error())
		http.Error(w, http.StatusText(500), 500)
	}
	return
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	log.Println("log: errorHandler")
	err := templates["error"].ExecuteTemplate(w, "layout", map[string]interface{}{"Error": http.StatusText(status), "Status": status})
	if err != nil {
		log.Println("log: errorHandler->error: " + err.Error())
		http.Error(w, http.StatusText(500), 500)
	}
	return
}

//********** User **********************************************************************************************************************************************

func (u *user) Create() {
	u.Name = "N/A"
	u.Auth = false
}

func (u *user) setAuth(auth bool) {
	u.Auth = auth
}

func (u *user) getAuth() bool {
	return u.Auth
}

func (u *user) setFileKeys(fileKeys string) {
	u.FileKeys = fileKeys
}

func (u *user) getFileKeys() string {
	return u.FileKeys
}
