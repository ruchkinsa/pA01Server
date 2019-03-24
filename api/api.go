package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"

	//"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ruchkinsa/pA01Server/database"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
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

var u User

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

	u.create(cfg.DbConnect)
	u.setFileKeys(path.Join(cfg.PublicPath, cfg.NameFile))
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
		products, err := u.getDbProductsAll()
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}
		p := Page{Title: "products", Products: products, Auth: u.getAuth()}
		renderTemplate(w, r, "products", &p)
	})
}

func productSaveHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Status bool    `json:"status"`
		Error  string  `json:"error"`
		Data   Product `json:"data"`
	}
	var result resultJSON
	result.Status = true
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		result.Status = false
		result.Error = "id - " + err.Error()
	}
	result.Data.ID = id
	if result.Data.Name = r.FormValue("name"); result.Data.Name == "" {
		result.Status = false
		result.Error = "text - null"
	}
	if result.Data.Version = r.FormValue("version"); result.Data.Version == "" {
		result.Status = false
		result.Error = "expirationDate - null"
	}
	if err := u.productSave(&result.Data); err != nil {
		result.Status = false
		result.Error = "testerror"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func keysHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//keys, err := loadKeys(u.getFileKeys())
		keys, err := u.getDbKeysAll()
		if err != nil {
			errorHandler(w, r, http.StatusBadRequest)
			return
		}
		p := Page{Title: "keys", Keys: keys, Auth: u.getAuth()}
		renderTemplate(w, r, "keys", &p)
	})
}

func keySaveHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Status bool   `json:"status"`
		Error  string `json:"error"`
		Data   Key    `json:"data"`
	}
	var result resultJSON
	result.Status = true
	id, err := strconv.Atoi(r.FormValue("id"))
	if err != nil {
		result.Status = false
		result.Error = "Произошла ошибка: " + err.Error()
	}
	result.Data.ID = id
	if result.Data.ExpirationDate = r.FormValue("expirationDate"); result.Data.ExpirationDate == "" {
		result.Status = false
		result.Error = "Произошла ошибка: expirationDate -> null"
	}
	if result.Data.IDStatus, err = strconv.Atoi(r.FormValue("status")); err != nil {
		result.Status = false
		result.Error = "Произошла ошибка: " + err.Error()
	}
	if result.Data.IDType, err = strconv.Atoi(r.FormValue("type")); err != nil {
		result.Status = false
		result.Error = "Произошла ошибка: " + err.Error()
	}
	if result.Data.IDProduct, err = strconv.Atoi(r.FormValue("product")); err != nil {
		result.Status = false
		result.Error = "Произошла ошибка: " + err.Error()
	}
	if err := u.keySave(&result.Data); err != nil {
		result.Status = false
		result.Error = "Произошла ошибка при сохранении данных"
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
	if err = u.keyDelete(idKey); err != nil {
		errorHandler(w, r, http.StatusBadRequest)
		return
	}
	// redirect to URL
	http.Redirect(w, r, "/keys", 303)
	return
}

func getTableStatusHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Status bool   `json:"status"`
		Error  string `json:"error"`
		Data   []Spr  `json:"data"`
	}
	var result resultJSON
	result.Status = true
	var err error
	if result.Data, err = u.getTableStatus(); err != nil {
		result.Status = false
		result.Error = "Ошибка запроса таблицы статусов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func getTableTypesHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Status bool   `json:"status"`
		Error  string `json:"error"`
		Data   []Spr  `json:"data"`
	}
	var result resultJSON
	result.Status = true
	var err error
	if result.Data, err = u.getTableTypes(); err != nil {
		result.Status = false
		result.Error = "Ошибка запроса таблицы статусов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func getTableProductsHandler(w http.ResponseWriter, r *http.Request) {
	type resultJSON struct {
		Status bool   `json:"status"`
		Error  string `json:"error"`
		Data   []Spr  `json:"data"`
	}
	var result resultJSON
	result.Status = true
	var err error
	if result.Data, err = u.getTableProducts(); err != nil {
		result.Status = false
		result.Error = "Ошибка запроса таблицы продуктов"
	}
	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func testLicenseHandler(w http.ResponseWriter, r *http.Request) {
	p := Page{Title: "Test", Auth: u.getAuth()}
	renderTemplate(w, r, "test", &p)
}

func licenseCheckHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	//log.Println("Form: ", r.Form)

	type resultJSON struct {
		Status bool   `json:"status"`
		Error  string `json:"error"`
	}
	var result resultJSON
	var keyID int
	if keyID, result.Error = u.getIDKeyFindLic(r.FormValue("keyPublicN"), r.FormValue("keyPublicE")); result.Error != "" {
		result.Status = false
		// добавить запись в Logs
	} else {
		result.Status, result.Error = u.checkLicenseKey(keyID, r.FormValue("keyText"))
		// добавить запись в Logs
	}

	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

func licenseActivateHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	type resultJSON struct {
		Status    bool   `json:"status"`
		Error     string `json:"error"`
		Key       string `json:"key"`
		Signature string `json:"signature"`
	}
	var result resultJSON
	var keyID int
	if keyID, result.Error = u.getIDKeyFindLic(r.FormValue("keyPublicN"), r.FormValue("keyPublicE")); result.Error != "" {
		result.Status = false
		// добавить запись в Logs
	} else {
		if result.Key, result.Signature, result.Error = u.generateLicenseKey(keyID); result.Error != "" {
			result.Status = false
			// добавить запись в Logs
		} else {
			result.Status = true
			// добавить запись в Logs
		}
	}

	js, _ := json.Marshal(result)
	fmt.Fprintf(w, string(js))
}

//********** Routes: default **********************************************************************************************************************************************

func indexHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Page{Title: "Home", Body: template.HTML("<p>Home Page</p>"), Auth: u.getAuth()}
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
		if u.loginCheck(login, password) {
			u.setAuth(true)
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
	u.setAuth(false)
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

//********** User **********************************************************************************************************************************************

func (u *User) create(db database.Config) {
	u.Name = "N/A"
	u.Auth = false
	u.Db = db
}

func (u *User) setAuth(auth bool) {
	u.Auth = auth
}

func (u *User) getAuth() bool {
	return u.Auth
}

func (u *User) setFileKeys(fileKeys string) {
	u.FileKeys = fileKeys
}

func (u *User) getFileKeys() string {
	return u.FileKeys
}

func (u *User) setDb(db database.Config) {
	u.Db = db
}

func (u *User) loginCheck(login, password string) bool {
	db := u.Db.DbConn.DbConn
	row := db.QueryRow("SELECT count(id) FROM users WHERE login = ? and password = ?", login, password)
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 || err != nil {
		log.Println("log func loginCheck -> error: ", err)
		return false
	}
	return true
}

func (u *User) getDbKeysAll() ([]Key, error) {
	db := u.Db.DbConn.DbConn
	keys := make([]Key, 0)
	if err := db.Select(&keys, "select l.id,l.keyText,l.keyPublicN,l.keyPublicE,p.name as product,s.name as status,t.name as typeLic,l.lastUsed,l.expirationDate from licenses l left join license_status s on l.idStatus=s.id left join products p on l.idProduct=p.id left join license_types t on l.idType=t.id"); err != nil {
		log.Println("log: getDbKeysAll -> error: ", err.Error())
		return nil, err
	}
	return keys, nil
}

func (u *User) keySave(key *Key) error {
	db := u.Db.DbConn.DbConn
	if key.ID == 0 {
		t := time.Now().Format("2006-01-02 15:04:05")
		// генерация keyPrivate для key
		privateKey, err := rsa.GenerateKey(rand.Reader, cryptoSetting.bits)
		if err != nil {
			log.Println("log: func keySave -> error: ", err.Error())
			return err
		}
		key.KeyPublicN = privateKey.PublicKey.N.String()
		key.KeyPublicE = strconv.Itoa(privateKey.PublicKey.E)
		key.KeyPrivateD = privateKey.D.String()
		key.KeyPrivatePrimes = ""
		for _, prime := range privateKey.Primes {
			key.KeyPrivatePrimes += " " + prime.String()
		}
		key.KeyPrivatePrecomputedDp = privateKey.Precomputed.Dp.String()
		key.KeyPrivatePrecomputedDq = privateKey.Precomputed.Dq.String()
		key.KeyPrivatePrecomputedQinv = privateKey.Precomputed.Qinv.String()
		key.KeyPrivatePrecomputedCRTValueExp = ""
		key.KeyPrivatePrecomputedCRTValueCoeff = ""
		key.KeyPrivatePrecomputedCRTValueR = ""
		for _, crtv := range privateKey.Precomputed.CRTValues {
			key.KeyPrivatePrecomputedCRTValueExp += " " + crtv.Exp.String()
			key.KeyPrivatePrecomputedCRTValueCoeff += " " + crtv.Coeff.String()
			key.KeyPrivatePrecomputedCRTValueR += " " + crtv.R.String()
		}
		key.KeyText = "N/A"
		rec, err := db.Exec("INSERT INTO licenses (keyText,idProduct,idStatus,idtype,expirationDate,keyPublicN, keyPublicE, keyPrivateD, keyPrivatePrimes, keyPrivatePrecomputedDp, keyPrivatePrecomputedDq, keyPrivatePrecomputedQinv, keyPrivatePrecomputedCRTValueExp, keyPrivatePrecomputedCRTValueCoeff, keyPrivatePrecomputedCRTValueR) VALUES('" + key.KeyText + "'," + strconv.Itoa(key.IDProduct) + "," + strconv.Itoa(key.IDStatus) + "," + strconv.Itoa(key.IDType) + ",'" + t + "','" + key.KeyPublicN + "','" + key.KeyPublicE + "','" + key.KeyPrivateD + "','" + strings.TrimLeft(key.KeyPrivatePrimes, " ") + "','" + key.KeyPrivatePrecomputedDp + "','" + key.KeyPrivatePrecomputedDq + "','" + key.KeyPrivatePrecomputedQinv + "','" + strings.TrimLeft(key.KeyPrivatePrecomputedCRTValueExp, " ") + "','" + strings.TrimLeft(key.KeyPrivatePrecomputedCRTValueCoeff, " ") + "','" + strings.TrimLeft(key.KeyPrivatePrecomputedCRTValueR, " ") + "');")
		if err != nil {
			log.Println("log: func keySave -> error: ", err.Error())
			return err
		}
		id, err := rec.LastInsertId()
		if err != nil {
			log.Println("log: func keySave -> error: ", err.Error())
			return err
		}
		key.ID = int(id)
	} else {
		if _, err := db.Exec("UPDATE `licenses` SET idStatus=" + strconv.Itoa(key.IDStatus) + ",idType=" + strconv.Itoa(key.IDType) + ",expirationDate='" + key.ExpirationDate + "' WHERE id=" + strconv.Itoa(key.ID)); err != nil {
			log.Println("log: func keySave -> error: ", err.Error())
			return err
		}
	}
	return nil
}

func (u *User) keyDelete(id int) error {
	db := u.Db.DbConn.DbConn
	if _, err := db.Exec("DELETE FROM licenses where id=?", id); err != nil {
		log.Println("log: func keyDelete -> error: ", err.Error())
		return err
	}

	return nil
}
func (u *User) getDbProductsAll() ([]Product, error) {
	db := u.Db.DbConn.DbConn
	products := make([]Product, 0)
	if err := db.Select(&products, "SELECT id,name,keyPublicN,keyPublicE,version FROM products"); err != nil {
		log.Println("log: func getDbProductsAll -> error: ", err.Error())
		return nil, err
	}
	return products, nil
}

func (u *User) productSave(product *Product) error {
	db := u.Db.DbConn.DbConn
	if product.ID == 0 {
		// генерация keyPrivate для product
		privateKey, err := rsa.GenerateKey(rand.Reader, cryptoSetting.bits)
		if err != nil {
			log.Println("log: func productSave -> error: ", err.Error())
			return err
		}
		product.KeyPublicN = privateKey.PublicKey.N.String()
		product.KeyPublicE = strconv.Itoa(privateKey.PublicKey.E)
		product.KeyPrivateD = privateKey.D.String()
		product.KeyPrivatePrimes = ""
		for _, prime := range privateKey.Primes {
			product.KeyPrivatePrimes += " " + prime.String()
		}
		product.KeyPrivatePrecomputedDp = privateKey.Precomputed.Dp.String()
		product.KeyPrivatePrecomputedDq = privateKey.Precomputed.Dq.String()
		product.KeyPrivatePrecomputedQinv = privateKey.Precomputed.Qinv.String()
		product.KeyPrivatePrecomputedCRTValueExp = ""
		product.KeyPrivatePrecomputedCRTValueCoeff = ""
		product.KeyPrivatePrecomputedCRTValueR = ""
		for _, crtv := range privateKey.Precomputed.CRTValues {
			product.KeyPrivatePrecomputedCRTValueExp += " " + crtv.Exp.String()
			product.KeyPrivatePrecomputedCRTValueCoeff += " " + crtv.Coeff.String()
			product.KeyPrivatePrecomputedCRTValueR += " " + crtv.R.String()
		}
		rec, err := db.Exec("INSERT INTO products (name,version,keyPublicN, keyPublicE, keyPrivateD, keyPrivatePrimes, keyPrivatePrecomputedDp, keyPrivatePrecomputedDq, keyPrivatePrecomputedQinv, keyPrivatePrecomputedCRTValueExp, keyPrivatePrecomputedCRTValueCoeff, keyPrivatePrecomputedCRTValueR) VALUES('" + product.Name + "','" + product.Version + "' ,'" + product.KeyPublicN + "','" + product.KeyPublicE + "','" + product.KeyPrivateD + "','" + strings.TrimLeft(product.KeyPrivatePrimes, " ") + "','" + product.KeyPrivatePrecomputedDp + "','" + product.KeyPrivatePrecomputedDq + "','" + product.KeyPrivatePrecomputedQinv + "','" + strings.TrimLeft(product.KeyPrivatePrecomputedCRTValueExp, " ") + "','" + strings.TrimLeft(product.KeyPrivatePrecomputedCRTValueCoeff, " ") + "','" + strings.TrimLeft(product.KeyPrivatePrecomputedCRTValueR, " ") + "');")
		if err != nil {
			log.Println("log: func productSave -> error: ", err.Error())
			return err
		}
		id, err := rec.LastInsertId()
		if err != nil {
			log.Println("log: func productSave -> error: ", err.Error())
			return err
		}
		product.ID = int(id)
	} else {
		if _, err := db.Exec("UPDATE products SET name='" + product.Name + "',version='" + product.Version + "' WHERE id=" + strconv.Itoa(product.ID)); err != nil {
			log.Println("log: func productSave -> error: ", err.Error())
			return err
		}
	}
	return nil
}

func (u *User) getTableStatus() ([]Spr, error) {
	db := u.Db.DbConn.DbConn
	status := make([]Spr, 0)
	if err := db.Select(&status, "SELECT id,name FROM license_status"); err != nil {
		log.Println("log: func getTableStatus -> error: ", err.Error())
		return nil, err
	}
	var data []Spr
	for _, rec := range status {
		data = append(data, Spr{rec.ID, rec.Name})
	}
	return data, nil
}

func win1251Toutf8(st string) (string, error) {
	sr := strings.NewReader(st)
	tr := transform.NewReader(sr, charmap.Windows1251.NewDecoder())
	buf, err := ioutil.ReadAll(tr)
	if err != err {
		return "", err
	}
	return string(buf), err // строка в UTF-8
}

func (u *User) getTableTypes() ([]Spr, error) {
	db := u.Db.DbConn.DbConn
	tupes := make([]Spr, 0)
	if err := db.Select(&tupes, "SELECT id,name FROM license_types"); err != nil {
		log.Println("log: func getTableTypes -> error: ", err.Error())
		return nil, err
	}
	var data []Spr
	for _, rec := range tupes {
		data = append(data, Spr{rec.ID, rec.Name})
	}
	return data, nil
}

func (u *User) getTableProducts() ([]Spr, error) {
	db := u.Db.DbConn.DbConn

	products := make([]Product, 0)
	if err := db.Select(&products, "SELECT id,name FROM products"); err != nil {
		log.Println("log: func getTableProducts -> error: ", err.Error())
		return nil, err
	}
	var data []Spr
	for _, rec := range products {
		data = append(data, Spr{rec.ID, rec.Name})
	}
	return data, nil
}

func (u *User) getIDKeyFindLic(keyPublicN string, keyPublicE string) (int, string) {
	db := u.Db.DbConn.DbConn

	if (keyPublicN == "") || (keyPublicE == "") {
		return 0, "Ошибка в данных запроса"
	}
	var key Key
	if err := db.Get(&key, "SELECT id, idStatus, idType, expirationDate, TIMESTAMPDIFF(SECOND,NOW(),`expirationDate`) as idProduct FROM licenses WHERE keyPublicN = '"+keyPublicN+"' and keyPublicE = '"+keyPublicE+"'"); err != nil {
		log.Println("log: func getIDKeyFindLic -> error: ", err.Error())
		return 0, "Ошибка: лицензия не найдена."
	}
	if key.IDStatus == 0 {
		return 0, "Ошибка: лицензия была блокирована, обратитесь в службу технической поддержки."
	}
	if (key.IDType == 2) && (key.IDProduct < 0) {
		return 0, "Ошибка: истек срок действия лицензии."
	}

	return key.ID, ""
}

func (u *User) checkLicenseKey(keyID int, keyText string) (bool, string) {
	db := u.Db.DbConn.DbConn
	var key Key
	if err := db.Get(&key, "SELECT keyText FROM licenses WHERE id = '"+strconv.Itoa(keyID)+"'"); err != nil {
		log.Println("log: func checkLicenseKey -> error: ", err.Error())
		return false, "Ошибка: лицензия не найдена."
	}
	if key.KeyText != keyText {
		return false, "Ошибка: ключ лицензии не актуален. Активируйте лицензию повторно после переустановки или обратитесь в службу технической поддержки."
	}

	return true, ""
}

func base64ToInt(s string) (*big.Int, error) { // []byte -> big.Int
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	i := new(big.Int)
	i.SetBytes(data)
	return i, nil
}
func stringToBigInt(s string) (*big.Int, bool) {
	return new(big.Int).SetString(strings.TrimSpace(s), 10)
	/*	new(big.Int).SetString(string, base)
		base - Базовый аргумент должен быть 0 или значением между 2 и MaxBase.
		Если база равна 0, префикс строки определяет фактическую базу преобразования.
		Префикс "0x" или "0X" выбирает базу 16; префикс "0" выбирает базу 8,
		а префикс "0b" или "0B" выбирает базу 2.
		В противном случае выбранная база равна 10.
	*/
}

func stringToRSApublicKey(publicN string, publicE string) (rsa.PublicKey, bool) {
	var keyPublic rsa.PublicKey
	var ok bool
	keyPublic.N, ok = stringToBigInt(publicN)
	if !ok {
		return keyPublic, false
	}
	keyPublic.E, _ = strconv.Atoi(publicE)
	return keyPublic, true
}

func stringToRSAprivateKey(keyPublicN string, keyPublicE string, keyPrivateD string, keyPrivatePrimes string, keyPrivatePrecomputedDp string, keyPrivatePrecomputedDq string, keyPrivatePrecomputedQinv string, keyPrivatePrecomputedCRTValueExp string, keyPrivatePrecomputedCRTValueCoeff string, keyPrivatePrecomputedCRTValueR string) (*rsa.PrivateKey, bool) {
	var keyPrivate rsa.PrivateKey
	var keyPublic rsa.PublicKey
	var ok bool
	keyPublic, ok = stringToRSApublicKey(keyPublicN, keyPublicE)
	if !ok {
		log.Println("log: func stringToRSAprivateKey -> error: stringToRSApublicKey")
		return nil, false
	}
	keyPrivate.PublicKey = keyPublic
	keyPrivate.D, ok = stringToBigInt(keyPrivateD)
	if !ok {
		log.Println("log: func stringToRSAprivateKey -> error: stringToBigInt")
		return nil, false
	}
	var primes []*big.Int
	var pr *big.Int
	for _, rec := range strings.Split(keyPrivatePrimes, " ") {
		pr, ok = stringToBigInt(rec)
		if !ok {
			log.Println("log: func stringToRSAprivateKey -> error: primes")
			return nil, false
		}
		primes = append(primes, pr)

	}
	keyPrivate.Primes = primes
	keyPrivate.Precomputed.Dp, ok = stringToBigInt(keyPrivatePrecomputedDp)
	if !ok {
		log.Println("log: func stringToRSAprivateKey -> error: Precomputed.Dp")
		return nil, false
	}
	keyPrivate.Precomputed.Dq, ok = stringToBigInt(keyPrivatePrecomputedDq)
	if !ok {
		log.Println("log: func stringToRSAprivateKey -> error: Precomputed.Dq")
		return nil, false
	}
	keyPrivate.Precomputed.Qinv, ok = stringToBigInt(keyPrivatePrecomputedQinv)
	if !ok {
		log.Println("log: func stringToRSAprivateKey -> error: Precomputed.Qinv")
		return nil, false
	}
	var mExp []*big.Int
	if keyPrivatePrecomputedCRTValueExp != "" {
		for _, rec := range strings.Split(keyPrivatePrecomputedCRTValueExp, " ") {
			pr, ok = stringToBigInt(rec)
			if !ok {
				log.Println("log: func stringToRSAprivateKey -> error: keyPrivatePrecomputedCRTValueExp")
				return nil, false
			}
			mExp = append(mExp, pr)
		}
	}
	var mCoeff []*big.Int
	if keyPrivatePrecomputedCRTValueCoeff != "" {
		for _, rec := range strings.Split(keyPrivatePrecomputedCRTValueCoeff, " ") {
			pr, ok = stringToBigInt(rec)
			if !ok {
				log.Println("log: func stringToRSAprivateKey -> error: keyPrivatePrecomputedCRTValueCoeff")
				return nil, false
			}
			mCoeff = append(mCoeff, pr)
		}
	}

	var mR []*big.Int
	if keyPrivatePrecomputedCRTValueR != "" {
		for _, rec := range strings.Split(keyPrivatePrecomputedCRTValueR, " ") {
			pr, ok = stringToBigInt(rec)
			if !ok {
				log.Println("log: func stringToRSAprivateKey -> error: keyPrivatePrecomputedCRTValueR")
				return nil, false
			}
			mR = append(mR, pr)
		}
	}
	if (len(mExp) != len(mCoeff)) || (len(mR) != len(mCoeff)) || (len(mExp) != len(mR)) {
		log.Println("log: func stringToRSAprivateKey -> error: if (len(mExp) != len(mCoeff)) || (len(mR) != len(mCoeff)) || (len(mExp) != len(mR))")
		return nil, false
	}
	var crtValues []rsa.CRTValue
	for i := 0; i < len(mExp); i++ {
		crtValues = append(crtValues, rsa.CRTValue{mExp[i], mCoeff[i], mR[i]})
	}
	keyPrivate.Precomputed.CRTValues = crtValues

	return &keyPrivate, true
}

func (u *User) generateLicenseKey(keyID int) (string, string, string) {
	db := u.Db.DbConn.DbConn
	var key Key
	if err := db.Get(&key, "select l.keyPublicN,l.keyPublicE, l.idProduct from licenses l WHERE l.id = '"+strconv.Itoa(keyID)+"'"); err != nil {
		log.Println("log: func generateLicenseKey -> error (db.Get(key)): ", err.Error())
		return "", "", "Ошибка: лицензия не найдена."
	}
	secretText := []byte("уникальное вычисляемое значение")
	var keyPublic rsa.PublicKey
	var ok bool
	keyPublic, ok = stringToRSApublicKey(key.KeyPublicN, key.KeyPublicE)
	if !ok {
		log.Println("log: func generateLicenseKey -> error: конвертации ключа keyPublic")
		return "", "", "Ошибка конвертации ключа."
	}
	keyText, err := rsa.EncryptOAEP(cryptoSetting.hash, cryptoSetting.random, &keyPublic, secretText, cryptoSetting.label)
	if err != nil {
		log.Println("log: func generateLicenseKey -> error (EncryptOAEP): ", err.Error())
		return "", "", "Ошибка: ключ лицензии не сформирован."
	}

	var product Product
	if err := db.Get(&product, "select keyPublicN, keyPublicE, keyPrivateD, keyPrivatePrimes, keyPrivatePrecomputedDp, keyPrivatePrecomputedDq, keyPrivatePrecomputedQinv, keyPrivatePrecomputedCRTValueExp, keyPrivatePrecomputedCRTValueCoeff, keyPrivatePrecomputedCRTValueR from licenses l WHERE id = '"+strconv.Itoa(key.IDProduct)+"'"); err != nil {
		log.Println("log: func generateLicenseKey -> error (db.QueryRow(product)): ", err.Error())
		return "", "", "Ошибка: продукт не найден."
	}
	var keyPrivate *rsa.PrivateKey
	keyPrivate, ok = stringToRSAprivateKey(product.KeyPublicN, product.KeyPublicE, product.KeyPrivateD, product.KeyPrivatePrimes, product.KeyPrivatePrecomputedDp, product.KeyPrivatePrecomputedDq, product.KeyPrivatePrecomputedQinv, product.KeyPrivatePrecomputedCRTValueExp, product.KeyPrivatePrecomputedCRTValueCoeff, product.KeyPrivatePrecomputedCRTValueR)
	if !ok {
		fmt.Println("log: func generateLicenseKey -> error: конвертации ключа ProductKeyPrivate")
		return "", "", "Ошибка конвертации ключа."
	}
	cryptoSetting.pssh.Write(keyText)
	signature, err := rsa.SignPSS(cryptoSetting.random, keyPrivate, cryptoSetting.signhash, cryptoSetting.pssh.Sum(nil), &cryptoSetting.opts)
	if err != nil {
		log.Println("log: func generateLicenseKey -> error (signature): ", err.Error())
		return "", "", "Ошибка создания подписи."
	}

	return fmt.Sprintf("%x", keyText), fmt.Sprintf("%x", signature), ""
}
