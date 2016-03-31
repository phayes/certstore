package main

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"log"
)

var (
	// Database Connection
	db *sqlx.DB

	// CRUD for User
	QueryCreateUser *sqlx.NamedStmt // QueryRow() (because we are using RETURNING)
	QueryReadUser   *sqlx.Stmt      // Get()
	QueryUpdateUser *sqlx.NamedStmt // Exec()
	QueryDeleteUser *sqlx.Stmt      // Exec()

	// CRUD for Cert
	QueryCreateCert *sqlx.NamedStmt // Exec()
	QueryReadCert   *sqlx.Stmt      // Get()
	QueryDeleteCert *sqlx.Stmt      // Exec()

	// Other miscellaneous queries
	QueryFetchUserCerts   *sqlx.Stmt // Select()
	QueryCertUpdateActive *sqlx.Stmt // Exec()
	QueryCertDeleteUsers  *sqlx.Stmt // Exec()

	// SQL for User CRUD
	SQLCreateUser = "INSERT INTO certstore_user(name,email) VALUES(:name, :email) RETURNING id"
	SQLReadUser   = "SELECT * from certstore_user WHERE id = $1"
	SQLUpdateUser = "UPDATE certstore_user SET name = :name, email = :email WHERE id = :id"
	SQLDeleteUser = "DELETE FROM certstore_user WHERE id = $1"

	// SQL for Cert CRUD
	SQLCreateCert = "INSERT INTO certstore_cert(id, userid, active, cert, key) VALUES(:id, :userid, :active, :cert, :key)"
	SQLReadCert   = "SELECT * from certstore_cert WHERE userid = $1 AND id = $2"
	SQLDeleteCert = "DELETE FROM certstore_cert WHERE userid = $1 AND id = $2"

	// SQL for miscallaneous queries
	SQLFetchUserCerts   = "SELECT * from certstore_cert WHERE userid = $1"
	SQLCertUpdateActive = "UPDATE certstore_cert SET active = $1 WHERE userid = $2 AND id = $3"
	SQLCertDeleteUsers  = "DELETE from certstore_cert WHERE userid = $1"
)

// Set-up the connection to the database on the global `db` connection.
// The caller is resonsible calling `defer DatabaseShutdown()`
func DatabaseSetup() error {
	var err error

	db, err = sqlx.Connect("postgres", OptDatabaseConnection)
	if err != nil {
		return err
	}

	err = DatabasePrepareQueries()
	if err != nil {
		return err
	}

	return nil
}

// Gracefully shutdown and close the database connection
func DatabaseShutdown() {
	err := db.Close()
	if err != nil {
		log.Println(err)
	}
}

// Prepare the database queries in the database upon startup
// By exclusively using prepared queries, we can gain some
// speedups in the database.
func DatabasePrepareQueries() error {
	var err error

	// CRUD for User
	QueryCreateUser, err = db.PrepareNamed(SQLCreateUser)
	if err != nil {
		return err
	}
	QueryReadUser, err = db.Preparex(SQLReadUser)
	if err != nil {
		return err
	}
	QueryUpdateUser, err = db.PrepareNamed(SQLUpdateUser)
	if err != nil {
		return err
	}
	QueryDeleteUser, err = db.Preparex(SQLDeleteUser)
	if err != nil {
		return err
	}

	// CRUD for Cert
	QueryCreateCert, err = db.PrepareNamed(SQLCreateCert)
	if err != nil {
		return err
	}
	QueryReadCert, err = db.Preparex(SQLReadCert)
	if err != nil {
		return err
	}
	QueryDeleteCert, err = db.Preparex(SQLDeleteCert)
	if err != nil {
		return err
	}

	// Other miscellaneous queries
	QueryFetchUserCerts, err = db.Preparex(SQLFetchUserCerts)
	if err != nil {
		return err
	}
	QueryCertUpdateActive, err = db.Preparex(SQLCertUpdateActive)
	if err != nil {
		return err
	}
	QueryCertDeleteUsers, err = db.Preparex(SQLCertDeleteUsers)
	if err != nil {
		return err
	}

	return nil
}

// Given a User, insert a row into the database
// If the user struct contains certificates, insert
// the certificates in a transaction safe manner.
func DatabaseCreateUser(user *User) error {
	// Use a transaction as to avoid a situation where a client could
	// read a new user with only a partial list of certificates
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	createUserStmt := tx.NamedStmt(QueryCreateUser)
	createCertStmt := tx.NamedStmt(QueryCreateCert)

	// Insert the user
	err = createUserStmt.Get(&user.Id, user)
	if err != nil {
		rollerr := tx.Rollback()
		if rollerr != nil {
			log.Println(rollerr)
		}
		return err
	}

	// If the User contains certificates, insert them as well
	if len(user.Certs) != 0 {
		for _, certData := range user.Certs {
			certData.UserId = user.Id
			_, err := createCertStmt.Exec(*certData)
			if err != nil {
				rollerr := tx.Rollback()
				if rollerr != nil {
					log.Println(rollerr)
				}
				return err
			}
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

// Given a userID, get a User
func DatabaseReadUser(userid string) (*User, error) {
	// Build the User struct
	user := new(User)
	err := QueryReadUser.Get(user, userid)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		} else {
			return nil, err
		}
	}

	// Attach the certs
	err = QueryFetchUserCerts.Select(&user.Certs, userid)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	return user, nil
}

// Given a partial User object, update the database record
func DatabaseUpdateUser(user *User) error {
	result, err := QueryUpdateUser.Exec(user)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); affected == 0 || err != nil {
		return ErrNotFound
	}
	return nil
}

// Given a user-id, delete a user. This will also delete the user's
// certificates in a transaction safe manner.
func DatabaseDeleteUser(userid string) error {
	// Use a transaction so as to avoid foreign key errors
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	deleteUserStmt := tx.Stmtx(QueryDeleteUser)
	deleteCertStmt := tx.Stmtx(QueryCertDeleteUsers)

	// Delete the certs
	_, err = deleteCertStmt.Exec(userid)
	if err != nil {
		rollerr := tx.Rollback()
		if rollerr != nil {
			log.Println(rollerr)
		}
		return err
	}

	// Delete the user
	res, err := deleteUserStmt.Exec(userid)
	if err != nil {
		rollerr := tx.Rollback()
		if rollerr != nil {
			log.Println(rollerr)
		}
		return err
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return err
	}

	// Check if we acutally deleted anything
	if affected, err := res.RowsAffected(); affected == 0 || err != nil {
		return ErrNotFound
	}

	// Sucessully deleted the user and their certificates
	return nil
}

// Given CertificateData, insert a row into the database
func DatabaseCreateCert(cert *CertificateData) error {
	// Insert the user
	_, err := QueryCreateCert.Exec(cert)
	if err != nil {
		return err
	}

	return nil
}

// Given a userID, get a User
func DatabaseReadCert(userid, certid string) (*CertificateData, error) {
	// Build the CertificateData struct
	cert := new(CertificateData)
	err := QueryReadCert.Get(cert, userid, certid)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		} else {
			return nil, err
		}
	}

	return cert, nil
}

// Update the certificate to mark it as active or inactive
func DatabaseUpdateCertActive(userid, certid string, active bool) error {
	result, err := QueryCertUpdateActive.Exec(userid, certid, active)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); affected == 0 || err != nil {
		return ErrNotFound
	}
	return nil
}

// Given a user-id, and a cert-id delete a certificate.
func DatabaseDeleteCert(userid, certid string) error {
	result, err := QueryDeleteCert.Exec(userid, certid)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); affected == 0 || err != nil {
		return ErrNotFound
	}
	return nil
}
