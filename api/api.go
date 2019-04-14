package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	//"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html/template"
	"io"

	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/ruchkinsa/pA01Server/database"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
)

type Config struct {
	// Configuration settings
	NameFile            string
	DbConnect           database.Config
	PublicPath          string
	PublicPathJS        http.FileSystem
	PublicPathCSS       http.FileSystem
	PublicPathTemplates http.FileSystem
}

type User struct {
	Name     string
	Auth     bool
	FileKeys string
	Db       database.Config
	//database.Db
}

type Key struct {
	ID                                 int    `db:"id"`
	KeyText                            string `db:"keyText"`
	KeyPublicN                         string `db:"keyPublicN"`
	KeyPublicE                         string `db:"keyPublicE"`
	KeyPrivateD                        string `db:"keyPrivateD"`
	KeyPrivatePrimes                   string `db:"keyPrivatePrimes"`
	KeyPrivatePrecomputedDp            string `db:"keyPrivatePrecomputedDp"`
	KeyPrivatePrecomputedDq            string `db:"keyPrivatePrecomputedDq"`
	KeyPrivatePrecomputedQinv          string `db:"keyPrivatePrecomputedQinv"`
	KeyPrivatePrecomputedCRTValueExp   string `db:"keyPrivatePrecomputedCRTValueExp"`
	KeyPrivatePrecomputedCRTValueCoeff string `db:"keyPrivatePrecomputedCRTValueCoeff"`
	KeyPrivatePrecomputedCRTValueR     string `db:"keyPrivatePrecomputedCRTValueR"`
	IDProduct                          int    `db:"idProduct"`
	Product                            string `db:"product"`
	IDStatus                           int    `db:"idStatus"`
	Status                             string `db:"status"`
	IDType                             int    `db:"idType"`
	TypeLic                            string `db:"typeLic"`
	LastUsed                           string `db:"lastUsed"`
	ExpirationDate                     string `db:"expirationDate"` // Timestamp time.Time -> Timestamp.Format("2006-01-02 15:04:05")
}

type Product struct {
	ID                                 int    `db:"id"`
	Name                               string `db:"name"`
	Version                            string `db:"version"`
	KeyPublicN                         string `db:"keyPublicN"`
	KeyPublicE                         string `db:"keyPublicE"`
	KeyPrivateD                        string `db:"keyPrivateD"`
	KeyPrivatePrimes                   string `db:"keyPrivatePrimes"`
	KeyPrivatePrecomputedDp            string `db:"keyPrivatePrecomputedDp"`
	KeyPrivatePrecomputedDq            string `db:"keyPrivatePrecomputedDq"`
	KeyPrivatePrecomputedQinv          string `db:"keyPrivatePrecomputedQinv"`
	KeyPrivatePrecomputedCRTValueExp   string `db:"keyPrivatePrecomputedCRTValueExp"`
	KeyPrivatePrecomputedCRTValueCoeff string `db:"keyPrivatePrecomputedCRTValueCoeff"`
	KeyPrivatePrecomputedCRTValueR     string `db:"keyPrivatePrecomputedCRTValueR"`
}

type recordLog struct {
	id          int    `db:"id"`
	eventDate   string `db:"eventDate"`
	eventIDType int    `db:"eventIDType"`
	eventResult string `db:"eventResult"`
	note        string `db:"note"`
}

type Spr struct {
	ID   int    `db:"id"`
	Name string `db:"name"`
}

type Page struct {
	Title    string
	Body     template.HTML //[]byte
	Auth     bool
	Keys     []Key
	Products []Product
}

type errorJSON struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

type cryptoSettings struct {
	random   io.Reader
	bits     int
	hash     hash.Hash
	label    []byte
	opts     rsa.PSSOptions
	signhash crypto.Hash
	pssh     hash.Hash
}

type claimsJWT struct {
	Name string
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
var cryptoSetting cryptoSettings

var user User

var templates = make(map[string]*template.Template)

func init() {
	tokenAuth = jwtauth.New("HS512", []byte("secret"), nil)

	cryptoSetting.random = rand.Reader
	cryptoSetting.bits = 2048
	cryptoSetting.label = []byte("")
	cryptoSetting.hash = sha256.New()
	cryptoSetting.signhash = crypto.SHA256
	cryptoSetting.opts.SaltLength = rsa.PSSSaltLengthAuto
	cryptoSetting.pssh = crypto.SHA256.New()
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

	user.create(cfg.DbConnect)
	user.setFileKeys(path.Join(cfg.PublicPath, cfg.NameFile))
	//u.setDb(cfg.DbConnect)
	r := chi.NewRouter()
	// routers:
	// routers: protected
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth)) // Seek, verify and validate JWT tokens
		r.Use(jwtauth.Authenticator)       // можно переопределить этот метод проверки

		r.Route("/keys", func(rKeys chi.Router) {
			rKeys.Handle("/", keysHandler())
			rKeys.Post("/key/save", keySaveHandler)
			rKeys.Get("/key/{id}/delete", keyDeleteHandler)
		})
		r.Route("/db", func(rDb chi.Router) {
			rDb.Get("/getTStatus", getTableStatusHandler)
			rDb.Get("/getTTypes", getTableTypesHandler)
			rDb.Get("/getTProducts", getTableProductsHandler)
		})
		r.Route("/products", func(rProdects chi.Router) {
			rProdects.Handle("/", productsHandler())
			rProdects.Post("/product/save", productSaveHandler)
		})
		r.Route("/testing", func(rTest chi.Router) {
			rTest.Get("/", testLicenseHandler)
			rTest.Post("/license/check", licenseCheckHandler)
			rTest.Post("/license/activate", licenseActivateHandler)
		})
	})

	// routers: public
	r.Group(func(r chi.Router) {
		r.Route("/login", func(rLogin chi.Router) {
			rLogin.Post("/", authHandler()) // POST
			rLogin.Get("/", loginHandler)   // GET
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

func productsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		products, err := user.getDbProductsAll()
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}
		p := Page{Title: "products", Products: products, Auth: user.getAuth()}
		renderTemplate(w, r, "products", &p)
	})
}

func productSaveHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Error errorJSON `json:"error"`
		Data  Product   `json:"data"`
	}
	var result resultJSON
	result.Error.Status = true
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		result.Error.Status = false
		result.Error.Message = "id - " + err.Error()
	}
	result.Data.ID = id
	if result.Data.Name = r.FormValue("name"); result.Data.Name == "" {
		result.Error.Status = false
		result.Error.Message = "text - null"
	}
	if result.Data.Version = r.FormValue("version"); result.Data.Version == "" {
		result.Error.Status = false
		result.Error.Message = "expirationDate - null"
	}
	if err := user.productSave(&result.Data); err != nil {
		result.Error.Status = false
		result.Error.Message = "testerror"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func keysHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//keys, err := loadKeys(u.getFileKeys())
		keys, err := user.getDbKeysAll()
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}
		p := Page{Title: "keys", Keys: keys, Auth: user.getAuth()}
		renderTemplate(w, r, "keys", &p)
	})
}

func keySaveHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Error errorJSON `json:"error"`
		Data  Key       `json:"data"`
	}
	var result resultJSON
	result.Error.Status = true
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка: " + err.Error()
	}
	result.Data.ID = id
	if result.Data.ExpirationDate = r.FormValue("expirationDate"); result.Data.ExpirationDate == "" {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка: expirationDate -> null"
	}
	if result.Data.IDStatus, err = strconv.Atoi(r.FormValue("status")); err != nil {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка: " + err.Error()
	}
	if result.Data.IDType, err = strconv.Atoi(r.FormValue("type")); err != nil {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка: " + err.Error()
	}
	if result.Data.IDProduct, err = strconv.Atoi(r.FormValue("product")); err != nil {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка: " + err.Error()
	}
	if err := user.keySave(&result.Data); err != nil {
		result.Error.Status = false
		result.Error.Message = "Произошла ошибка при сохранении данных"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func keyDeleteHandler(w http.ResponseWriter, r *http.Request) {
	idKey, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	if err = user.keyDelete(idKey); err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	// redirect to URL
	http.Redirect(w, r, "/keys", 303)
	return
}

func getTableStatusHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Error errorJSON `json:"error"`
		Data  []Spr     `json:"data"`
	}
	var result resultJSON
	result.Error.Status = true
	var err error
	if result.Data, err = user.getTableStatus(); err != nil {
		result.Error.Status = false
		result.Error.Message = "Ошибка запроса таблицы статусов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func getTableTypesHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Error errorJSON `json:"error"`
		Data  []Spr     `json:"data"`
	}
	var result resultJSON
	result.Error.Status = true
	var err error
	if result.Data, err = user.getTableTypes(); err != nil {
		result.Error.Status = false
		result.Error.Message = "Ошибка запроса таблицы статусов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func getTableProductsHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Error errorJSON `json:"error"`
		Data  []Spr     `json:"data"`
	}
	var result resultJSON
	result.Error.Status = true
	var err error
	if result.Data, err = user.getTableProducts(); err != nil {
		result.Error.Status = false
		result.Error.Message = "Ошибка запроса таблицы продуктов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func testLicenseHandler(w http.ResponseWriter, r *http.Request) {
	p := Page{Title: "Test", Auth: user.getAuth()}
	renderTemplate(w, r, "test", &p)
}

func licenseCheckHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var result errorJSON
	var keyID int
	if keyID, result.Message = user.getIDKeyFindLic(r.FormValue("keyPublicN"), r.FormValue("keyPublicE")); result.Message != "" {
		result.Status = false
		// добавить запись в Logs
		rec := recordLog{eventIDType: 1, eventResult: result.Message, note: "keyID=" + strconv.Itoa(keyID)}
		if err := user.saveLogs(rec); err != nil {
			log.Println("log: func licenseCheckHandler ->saveLogs -> error: ", err.Error())
		}
	} else {
		result.Status, result.Message = user.checkLicenseKey(keyID, r.FormValue("keyText"))
		// добавить запись в Logs
		rec := recordLog{eventIDType: 1, eventResult: result.Message, note: "keyID=" + strconv.Itoa(keyID)}
		if err := user.saveLogs(rec); err != nil {
			log.Println("log: func licenseCheckHandler ->saveLogs -> error: ", err.Error())
		}
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func licenseActivateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Error     errorJSON `json:"error"`
		Key       string    `json:"key"`
		Signature string    `json:"signature"`
	}
	var result resultJSON
	var keyID int
	if keyID, result.Error.Message = user.getIDKeyFindLic(r.FormValue("keyPublicN"), r.FormValue("keyPublicE")); result.Error.Message != "" {
		result.Error.Status = false
		// добавить запись в Logs
		rec := recordLog{eventIDType: 2, eventResult: result.Error.Message, note: "keyID=" + strconv.Itoa(keyID)}
		if err := user.saveLogs(rec); err != nil {
			log.Println("log: func licenseActivateHandler ->saveLogs -> error: ", err.Error())
		}
	} else {
		if result.Key, result.Signature, result.Error.Message = user.generateLicenseKey(keyID); result.Error.Message != "" {
			result.Error.Status = false
			// добавить запись в Logs
			rec := recordLog{eventIDType: 2, eventResult: result.Error.Message, note: "keyID=" + strconv.Itoa(keyID)}
			if err := user.saveLogs(rec); err != nil {
				log.Println("log: func licenseActivateHandler ->saveLogs -> error: ", err.Error())
			}
		} else {
			result.Error.Status = true
			// добавить запись в Logs
			rec := recordLog{eventIDType: 2, eventResult: "Лицензия сгенерирована", note: "keyID=" + strconv.Itoa(keyID)}
			if err := user.saveLogs(rec); err != nil {
				log.Println("log: func licenseActivateHandler ->saveLogs -> error: ", err.Error())
			}
		}
	}

	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

//********** Routes: default **********************************************************************************************************************************************

func indexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Page{Title: "Home", Body: template.HTML("<p>Home Page</p>"), Auth: user.getAuth()}
		//log.Printf("%+v", p)
		renderTemplate(w, r, "index", &p)
	})
}

//********** Routes: auth **********************************************************************************************************************************************

func loginHandler(w http.ResponseWriter, r *http.Request) {
	p := Page{Title: "Login", Body: template.HTML("<p>Login Page</p>")}
	renderTemplate(w, r, "login", &p)
}

func authHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		login := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if user.loginCheck(login, password) {
			user.setAuth(true)
			// создание и запись данных о пользователе в сессию/БД/cookie
			token, err := createTokenJWT(login)
			if err != nil {
				log.Println("Error creating JWT token: ", err)
				errorHandler(w, r, http.StatusInternalServerError)
				return
			}
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
			http.Redirect(w, r, "/products", 303)
			return
		}
		p := Page{Title: "Login", Body: template.HTML("<b>User not found!<b>")}
		renderTemplate(w, r, "login", &p)
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	user.setAuth(false)
	jwtCookie := http.Cookie{Name: "jwt", Value: "", HttpOnly: false, Path: "/", MaxAge: -1, Expires: time.Unix(0, 0)}
	http.SetCookie(w, &jwtCookie)
	// redirect to URL
	http.Redirect(w, r, "/", 303)
	return
}

func createTokenJWT(login string) (string, error) {
	claims := claimsJWT{
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
	err := templates["error"].ExecuteTemplate(w, "layout", map[string]interface{}{"Error": http.StatusText(404), "Status": 404})
	if err != nil {
		log.Println("log: error404Handler->error: " + err.Error())
		http.Error(w, http.StatusText(500), 500)
	}
	return
}

func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	err := templates["error"].ExecuteTemplate(w, "layout", map[string]interface{}{"Error": http.StatusText(status), "Status": status})
	if err != nil {
		log.Println("log: errorHandler->error: " + err.Error())
		http.Error(w, http.StatusText(500), 500)
	}
	return
}
