package api

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ruchkinsa/pA01Server/database"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
)

//********** User **********************************************************************************************************************************************

func (user *User) create(db database.Config) {
	user.Name = "N/A"
	user.Auth = false
	user.Db = db
}
func (user *User) setAuth(auth bool) {
	user.Auth = auth
}
func (user *User) getAuth() bool {
	return user.Auth
}
func (user *User) loginCheck(login, password string) bool {
	db := user.Db.DbConn.DbConn
	row := db.QueryRow("SELECT count(id) FROM users WHERE login = ? and password = ?", login, password)
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 || err != nil {
		log.Println("log func loginCheck -> error: ", err)
		return false
	}
	return true
}

func (user *User) setFileKeys(fileKeys string) {
	user.FileKeys = fileKeys
}

func (user *User) getFileKeys() string {
	return user.FileKeys
}

func (user *User) setDb(db database.Config) {
	user.Db = db
}

func (user *User) getDbKeysAll() ([]Key, error) {
	db := user.Db.DbConn.DbConn
	keys := make([]Key, 0)
	if err := db.Select(&keys, "select l.id,l.keyText,l.keyPublicN,l.keyPublicE,p.name as product,s.name as status,t.name as typeLic,l.lastUsed,l.expirationDate from licenses l left join license_status s on l.idStatus=s.id left join products p on l.idProduct=p.id left join license_types t on l.idType=t.id"); err != nil {
		log.Println("log: getDbKeysAll -> error: ", err.Error())
		return nil, err
	}
	return keys, nil
}

func (user *User) keySave(key *Key) error {
	db := user.Db.DbConn.DbConn
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

func (user *User) keyDelete(id int) error {
	db := user.Db.DbConn.DbConn
	if _, err := db.Exec("DELETE FROM licenses where id=?", id); err != nil {
		log.Println("log: func keyDelete -> error: ", err.Error())
		return err
	}

	return nil
}
func (user *User) getDbProductsAll() ([]Product, error) {
	db := user.Db.DbConn.DbConn
	products := make([]Product, 0)
	if err := db.Select(&products, "SELECT id,name,keyPublicN,keyPublicE,version FROM products"); err != nil {
		log.Println("log: func getDbProductsAll -> error: ", err.Error())
		return nil, err
	}
	return products, nil
}

func (user *User) productSave(product *Product) error {
	db := user.Db.DbConn.DbConn
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

func (user *User) getTableStatus() ([]Spr, error) {
	db := user.Db.DbConn.DbConn
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

func (user *User) getTableTypes() ([]Spr, error) {
	db := user.Db.DbConn.DbConn
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

func (user *User) getTableProducts() ([]Spr, error) {
	db := user.Db.DbConn.DbConn

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

func (user *User) getIDKeyFindLic(keyPublicN string, keyPublicE string) (int, string) {
	db := user.Db.DbConn.DbConn

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

func (user *User) checkLicenseKey(keyID int, keyText string) (bool, string) {
	db := user.Db.DbConn.DbConn
	var key Key
	if err := db.Get(&key, "SELECT keyText FROM licenses WHERE id = '"+strconv.Itoa(keyID)+"'"); err != nil {
		log.Println("log: func checkLicenseKey -> error: ", err.Error())
		return false, "Ошибка: лицензия не найдена."
	}
	if key.KeyText != keyText {
		return false, "Ошибка: ключ лицензии не актуален. Активируйте лицензию повторно после переустановки или обратитесь в службу технической поддержки."
	}

	return true, "Лицензия действительна"
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

func splitStringToArrayBigInt(str string, separator string) ([]*big.Int, bool) {
	var arrayBigInt []*big.Int
	if str != "" {
		var bigInt *big.Int
		var ok bool
		for _, rec := range strings.Split(str, separator) {
			if bigInt, ok = stringToBigInt(rec); !ok {
				return nil, false
			}
			arrayBigInt = append(arrayBigInt, bigInt)
		}
	}
	return arrayBigInt, true
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

func stringKeyToRSAprivateKey(product Product) (*rsa.PrivateKey, bool) {
	var keyPrivate rsa.PrivateKey
	var keyPublic rsa.PublicKey
	var ok bool
	if keyPublic, ok = stringToRSApublicKey(product.KeyPublicN, product.KeyPublicE); !ok {
		return nil, false
	}
	keyPrivate.PublicKey = keyPublic

	if keyPrivate.D, ok = stringToBigInt(product.KeyPrivateD); !ok {
		return nil, false
	}
	if keyPrivate.Primes, ok = splitStringToArrayBigInt(product.KeyPrivatePrimes, " "); !ok {
		return nil, false
	}
	if keyPrivate.Precomputed.Dp, ok = stringToBigInt(product.KeyPrivatePrecomputedDp); !ok {
		return nil, false
	}
	if keyPrivate.Precomputed.Dq, ok = stringToBigInt(product.KeyPrivatePrecomputedDq); !ok {
		return nil, false
	}
	if keyPrivate.Precomputed.Qinv, ok = stringToBigInt(product.KeyPrivatePrecomputedQinv); !ok {
		return nil, false
	}
	var mExp []*big.Int
	if mExp, ok = splitStringToArrayBigInt(product.KeyPrivatePrecomputedCRTValueExp, " "); !ok {
		return nil, false
	}
	var mCoeff []*big.Int
	if mCoeff, ok = splitStringToArrayBigInt(product.KeyPrivatePrecomputedCRTValueCoeff, " "); !ok {
		return nil, false
	}
	var mR []*big.Int
	if mR, ok = splitStringToArrayBigInt(product.KeyPrivatePrecomputedCRTValueR, " "); !ok {
		return nil, false
	}
	if (len(mExp) != len(mCoeff)) || (len(mR) != len(mCoeff)) || (len(mExp) != len(mR)) {
		return nil, false
	}
	var crtValues []rsa.CRTValue
	for i := 0; i < len(mExp); i++ {
		crtValues = append(crtValues, rsa.CRTValue{mExp[i], mCoeff[i], mR[i]})
	}
	keyPrivate.Precomputed.CRTValues = crtValues
	return &keyPrivate, true
}

func (user *User) generateLicenseKey(keyID int) (string, string, string) {
	db := user.Db.DbConn.DbConn
	var key Key
	if err := db.Get(&key, "select l.keyPublicN,l.keyPublicE, l.idProduct from licenses l WHERE l.id = '"+strconv.Itoa(keyID)+"'"); err != nil {
		log.Println("log: func generateLicenseKey -> error (db.Get(key)): ", err.Error())
		return "", "", "Ошибка: лицензия не найдена."
	}
	secretText := []byte("уникальное вычисляемое значение")
	var keyPublic rsa.PublicKey
	var ok bool
	if keyPublic, ok = stringToRSApublicKey(key.KeyPublicN, key.KeyPublicE); !ok {
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
	if keyPrivate, ok = stringKeyToRSAprivateKey(product); !ok {
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

func (user *User) saveLogs(rec recordLog) error {
	db := user.Db.DbConn.DbConn
	recCur, err := db.Exec("INSERT INTO logs (eventIDType, eventResult, note) VALUES(" + strconv.Itoa(rec.eventIDType) + ",'" + rec.eventResult + "','" + rec.note + "');")
	if err != nil {
		log.Println("log: func saveLogs -> error: ", err.Error())
		return err
	}
	if _, err := recCur.LastInsertId(); err != nil {
		log.Println("log: func saveLogs -> error: ", err.Error())
		return err
	}
	return nil
}
