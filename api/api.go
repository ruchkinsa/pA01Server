package api

import (
	"bufio"
	//"encoding/json"
	//"fmt"
	"html/template"
	//"io"
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

type page struct {
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

	u.Create()
	u.setFileKeys(path.Join(cfg.PublicPath, cfg.NameFile))
	r := chi.NewRouter()
	// routers:
	// routers: protected
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth)) // Seek, verify and validate JWT tokens
		r.Use(jwtauth.Authenticator)       // можно переопределить этот метод проверки

		r.Handle("/keys", keysHandler())
		r.Get("/key/add", keyAddHandler)
	})

	// routers: public
	r.Group(func(r chi.Router) {
		r.Route("/login", func(r chi.Router) {
			r.Post("/", authHandler()) // POST
			r.Get("/", loginHandler)   // GET
		})
		r.Handle("/", indexHandler())
		r.Get("/logout", logoutHandler)
		// ways static data
		r.Handle("/css/*", http.StripPrefix("/css/", http.FileServer(cfg.PublicPathCSS)))
		r.Handle("/js/*", http.StripPrefix("/js/", http.FileServer(cfg.PublicPathJS)))
		r.Handle("/templates/*", http.StripPrefix("/templates/", http.FileServer(cfg.PublicPathTemplates)))
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
		/*js, err := json.Marshal(keys)
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}		*/
		//fmt.Fprintf(w, string(js))
		p := page{Title: "keys", Keys: keys}
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
	//http.Redirect(w, r, "/keys", 301)

	keys, err := loadKeys(u.getFileKeys())
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	/*js, err := json.Marshal(keys)
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}		*/
	//fmt.Fprintf(w, string(js))
	p := page{Title: "keys", Keys: keys}
	renderTemplate(w, r, "keys", &p)
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
		k.Id = cols[0] //strconv.Atoi(cols[0])
		k.Text = cols[1]
		k.ExpirationDate = cols[2]
		k.LastUsed = cols[3]
		k.IsBlosed = cols[4]
		keys = append(keys, k)
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
	defer file.Close()
	scanner := bufio.NewScanner(file)
	col := 1
	for scanner.Scan() {
		col++
		if err = scanner.Err(); err != nil {
			break
		}
	}

	var rec string
	rec = strconv.Itoa(col)
	rec += "|" + "key" + strconv.Itoa(col)
	t := time.Now()
	rec += "|" + t.Format("2006-01-02 15:04:05")
	rec += "|" + t.Format("2006-01-02 15:04:05")
	rec += "|false"

	log.Println(rec)

	file.WriteString(rec)
	return nil
}

//********** Routes: default **********************************************************************************************************************************************

func indexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("indexHandler")
		auth := "false"
		if u.getAuth() {
			auth = "true"
		}
		log.Println("indexHandler: .Auth =", auth)
		p := page{Title: "Home", Body: template.HTML("<p>Home page</p>"), Auth: u.getAuth()}
		//renderTemplate(w, r, "index", &p)
		renderTemplate(w, r, "index", &p)
	})
}

//********** Routes: auth **********************************************************************************************************************************************

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("loginHandler")
	p := page{Title: "Login", Body: template.HTML("<p>Login page</p>")}
	renderTemplate(w, r, "login", &p)
}

func authHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("authHandler")
		login := r.PostFormValue("username")
		password := r.PostFormValue("password")
		log.Println("authHandler->login: " + login)
		log.Println("authHandler->password: " + password)
		if login == "admin" && password == "password" {
			auth := "false"
			if u.getAuth() {
				auth = "true"
			}
			log.Println("authHandler: .Auth1 =", auth)
			u.setAuth(true)
			auth = "false"
			if u.getAuth() {
				auth = "true"
			}
			log.Println("authHandler: .Auth2 =", auth)
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
			jwtCookie.Expires = time.Now().Add(time.Hour * 12)
			http.SetCookie(w, jwtCookie)
			// redirect to URL
			http.Redirect(w, r, "/keys", 301)
		}
		p := page{Title: "Login", Body: template.HTML("<b>User not found!<b>")}
		renderTemplate(w, r, "login", &p)
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("logoutHandler")
	auth := "false"
	if u.getAuth() {
		auth = "true"
	}
	log.Println("logoutHandler: .Auth3 =", auth)
	u.setAuth(false)
	auth = "false"
	if u.getAuth() {
		auth = "true"
	}
	log.Println("logoutHandler: .Auth4 =", auth)
	// redirect to URL
	http.Redirect(w, r, "/", 301)
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
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	log.Println("log: errorHandler")
	err := templates["error"].ExecuteTemplate(w, "layout", map[string]interface{}{"Error": http.StatusText(status), "Status": status})
	if err != nil {
		log.Println("log: errorHandler->error: " + err.Error())
		http.Error(w, http.StatusText(500), 500)
	}
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
