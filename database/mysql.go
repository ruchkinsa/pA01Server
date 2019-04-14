package database

import (
	"database/sql"
	_ "database/sql"
	_ "encoding/json"

	// "log"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type Config struct {
	ConnectString string
	DbConn        *sqlDb
}

type sqlDb struct {
	DbConn            *sqlx.DB
	sqlSelectProducts *sqlx.Stmt
	sqlInsertUser     *sqlx.NamedStmt
	sqlLoginUser      *sqlx.Stmt
}

func InitDb(cfg Config) (*sqlDb, error) {
	if dbConn, err := sqlx.Connect("mysql", cfg.ConnectString); err != nil {
		return nil, err
	} else {
		p := &sqlDb{DbConn: dbConn}
		if err := p.DbConn.Ping(); err != nil {
			return nil, err
		}
		// указываем кодировку utf8 для соединения
		if rows, err := p.DbConn.Query("SET NAMES 'utf8'"); err != nil {
			return nil, err
		} else {
			rows.Close()
		}
		if err := p.createTablesIfNotExist(); err != nil {
			return nil, err
		}
		if err := p.prepareSqlStatements(); err != nil {
			return nil, err
		}
		return p, nil
	}
}

func (p *sqlDb) createTablesIfNotExist() error {
	create_sql := `
       CREATE TABLE IF NOT EXISTS users (
       id SERIAL NOT NULL PRIMARY KEY,
       name TEXT NOT NULL,
       login TEXT NOT NULL,
       password TEXT NOT NULL);`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}
	row := p.DbConn.QueryRow("SELECT count(id) FROM users WHERE login = 'admin'")
	var countAdmin int
	if err := row.Scan(&countAdmin); err == sql.ErrNoRows || countAdmin == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO users(name,login,password) VALUES('Administrator','admin','password')"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	create_sql = `
	CREATE TABLE IF NOT EXISTS products (
		id SERIAL NOT NULL PRIMARY KEY,
		name TEXT NOT NULL,       
		version TEXT NOT NULL,       
		keyPublicN TEXT NOT NULL,
		keyPublicE TEXT NOT NULL,
		keyPrivateD TEXT NOT NULL,  
		keyPrivatePrimes TEXT NOT NULL, 
		keyPrivatePrecomputedDp TEXT NOT NULL,
		keyPrivatePrecomputedDq TEXT NOT NULL,
		keyPrivatePrecomputedQinv TEXT NOT NULL,
		keyPrivatePrecomputedCRTValueExp TEXT,
		keyPrivatePrecomputedCRTValueCoeff TEXT,
		keyPrivatePrecomputedCRTValueR TEXT		
		);`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}

	create_sql = `
       CREATE TABLE IF NOT EXISTS license_status (
       id INT NOT NULL PRIMARY KEY,
       name TEXT NOT NULL
       );`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}
	row = p.DbConn.QueryRow("SELECT count(id) FROM license_status")
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_status (id, name) VALUES(0, 'Bloked'),(1, 'N/A'),(2, 'Actived');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	create_sql = `
       CREATE TABLE IF NOT EXISTS license_types (
       id INT NOT NULL PRIMARY KEY,
       name TEXT NOT NULL
       );`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}
	row = p.DbConn.QueryRow("SELECT count(id) FROM license_types")
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_types (id, name) VALUES(1, 'Постоянная'),(2, 'Временная');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	create_sql = `
      CREATE TABLE IF NOT EXISTS licenses (
       id SERIAL NOT NULL PRIMARY KEY,
       text TEXT NOT NULL,       
        keyPublicN TEXT NOT NULL,
		keyPublicE TEXT NOT NULL,
		keyPrivateD TEXT NOT NULL,  
		keyPrivatePrimes TEXT NOT NULL, 
		keyPrivatePrecomputedDp TEXT NOT NULL,
		keyPrivatePrecomputedDq TEXT NOT NULL,
		keyPrivatePrecomputedQinv TEXT NOT NULL,
		keyPrivatePrecomputedCRTValueExp TEXT,
		keyPrivatePrecomputedCRTValueCoeff TEXT,
		keyPrivatePrecomputedCRTValueR TEXT,		
       idProduct BIGINT NOT NULL,      
	   idStatus INT NOT NULL,  	
	   idType INT NOT NULL,   
       lastUsed TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP,
       expirationDate TIMESTAMP NOT NULL       
       );`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}

	create_sql = `
       CREATE TABLE IF NOT EXISTS log_types (
       id INT NOT NULL PRIMARY KEY,
       name VARCHAR(50) NOT NULL
       );`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}
	row = p.DbConn.QueryRow("SELECT count(id) FROM log_types")
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_types (id, name) VALUES(1, 'Checking license'),(2, 'Activate license');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	create_sql = `
       CREATE TABLE IF NOT EXISTS logs (
	   id SERIAL NOT NULL PRIMARY KEY,
	   eventDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	   eventIDType INT NOT NULL,
	   eventResult VARCHAR(250) NOT NULL,
	   note	varchar(250)
       );`
	if rows, err := p.DbConn.Query(create_sql); err != nil {
		return err
	} else {
		rows.Close()
	}

	return nil
}

func (p *sqlDb) prepareSqlStatements() (err error) {

	if p.sqlSelectProducts, err = p.DbConn.Preparex(
		"SELECT name, version FROM products",
	); err != nil {
		return err
	}
	if p.sqlInsertUser, err = p.DbConn.PrepareNamed(
		"INSERT INTO users (name, login, password) VALUES (:name, :login, :password) ", //+ "RETURNING id, name, login, password",
		//"INSERT INTO people (name, login, password) VALUES ( ?, ?, ? ) ", //+ "RETURNING id, name, login, password",
		/* использование:
		_, err = p.sqlInsertUser.Exec( "1", "A", "qwe") // Insert tuples (i, i^2)
		if err != nil {	panic(err.Error()) }
		*/
	); err != nil {
		return err
	}
	//defer p.sqlInsertUser.Close()

	if p.sqlLoginUser, err = p.DbConn.Preparex(
		"SELECT count(id) FROM users WHERE login = ? and password = ?",
		/* использование:
		var result
		err = stmtOut.QueryRow("Name").Scan(&result) // WHERE name = "Name"
		if err != nil {	panic(err.Error()) }
		*/

	); err != nil {
		return err
	}

	return nil
}
