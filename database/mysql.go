package database

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type Config struct {
	ConnectString string
	DbConn        *sqlDb
}

type sqlDb struct {
	DbConn *sqlx.DB
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
		return p, nil
	}
}

func (p *sqlDb) createTablesIfNotExist() error {

	if err := p.createTableUsers(); err != nil {
		return err
	}
	if err := p.createTableProducts(); err != nil {
		return err
	}
	if err := p.createTableLicenseTypes(); err != nil {
		return err
	}
	if err := p.createTableLicenseStatus(); err != nil {
		return err
	}
	if err := p.createTableLicenses(); err != nil {
		return err
	}
	if err := p.createTableLogTypes(); err != nil {
		return err
	}
	if err := p.createTableLogs(); err != nil {
		return err
	}
	return nil
}

func (p *sqlDb) createTableUsers() (err error) {
	createSQL := `
       CREATE TABLE IF NOT EXISTS users (
       id SERIAL NOT NULL PRIMARY KEY,
       name TEXT NOT NULL,
       login TEXT NOT NULL,
       password TEXT NOT NULL);`
	if rows, err := p.DbConn.Query(createSQL); err != nil {
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
	return nil
}

func (p *sqlDb) createTableProducts() (err error) {
	createSQL := `
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
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	return nil
}

func (p *sqlDb) createTableLicenseTypes() (err error) {
	createSQL := `
			CREATE TABLE IF NOT EXISTS license_types (
			id INT NOT NULL PRIMARY KEY,
			name TEXT NOT NULL
			);`
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	row := p.DbConn.QueryRow("SELECT count(id) FROM license_types")
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_types (id, name) VALUES(1, 'Постоянная'),(2, 'Временная');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (p *sqlDb) createTableLicenseStatus() (err error) {
	createSQL := `
		CREATE TABLE IF NOT EXISTS license_status (
		id INT NOT NULL PRIMARY KEY,
		name TEXT NOT NULL
		);`
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	row := p.DbConn.QueryRow("SELECT count(id) FROM license_status")
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_status (id, name) VALUES(0, 'Bloked'),(1, 'N/A'),(2, 'Actived');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (p *sqlDb) createTableLicenses() (err error) {
	createSQL := `
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
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	return nil
}

func (p *sqlDb) createTableLogTypes() (err error) {
	createSQL := `
			CREATE TABLE IF NOT EXISTS log_types (
			id INT NOT NULL PRIMARY KEY,
			name VARCHAR(50) NOT NULL
			);`
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	row := p.DbConn.QueryRow("SELECT count(id) FROM log_types")
	var countRecord int
	if err := row.Scan(&countRecord); err == sql.ErrNoRows || countRecord == 0 {
		if _, err := p.DbConn.Exec("INSERT INTO license_types (id, name) VALUES(1, 'Checking license'),(2, 'Activate license');"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (p *sqlDb) createTableLogs() (err error) {
	createSQL := `
		CREATE TABLE IF NOT EXISTS logs (
		id INT NOT NULL PRIMARY KEY,
		eventDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
		eventIDType INT NOT NULL,
		eventResult VARCHAR(250) NOT NULL,
		note	varchar(250)
		);`
	if rows, err := p.DbConn.Query(createSQL); err != nil {
		return err
	} else {
		rows.Close()
	}
	return nil
}
