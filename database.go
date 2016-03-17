package main

import (
	"database/sql"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"log"
	"strconv"
)

var (
	// Database Connection
	db *sqlx.DB

	// CRUD for User
	QueryCreateUser *sqlx.NamedStmt // Exec()
	QueryReadUser   *sqlx.Stmt      // Get()
	QueryUpdateUser *sqlx.NamedStmt // Exec()
	QueryDeleteUser *sqlx.Stmt      // Exec()

	// CRUD for Cert
	QueryCreateCert *sqlx.NamedStmt // Exec()
	QueryReadCert   *sqlx.Stmt      // Get()
	QueryUpdateCert *sqlx.NamedStmt // Exec()
	QueryDeleteCert *sqlx.Stmt      // Exec()

	// Other miscellaneous queries
	QueryFetchUserCerts   *sqlx.Stmt // Select()
	QueryFetchUserCertIds *sqlx.Stmt // Select()
	QueryCertUpdateActive *sqlx.Stmt // Exec()
	QueryCertDeleteUsers  *sqlx.Stmt // Exec()

	// SQL for User CRUD
	SQLCreateUser = "INSERT INTO user(name,email) VALUES(:name,:email) RETURNING id;"
	SQLReadUser   = "SELECT * from user WHERE id = $1;"
	SQLUpdateUser = "UPDATE user SET name = :name AND email = :email WHERE id = :id;"
	SQLDeleteUser = "BEGIN; DELETE FROM user WHERE id = $1; DELETE from certificate WHERE user = $1; COMMIT;"

	// SQL for Cert CRUD
	SQLCreateCert = "INSERT INTO certificate(id,user,active,cert,key) VALUES(:id,:user,:active,:cert,:key);"
	SQLReadCert   = "SELECT * from certificate WHERE user = $1 AND id = $2;"
	SQLUpdateCert = "UPDATE certificate SET active = :active AND cert = :cert AND key = :key WHERE user = :user AND id = :id;"
	SQLDeleteCert = "DELETE FROM certificate WHERE user = $1 AND id = $2;"

	// SQL for miscallaneous queries
	SQLFetchUserCerts   = "SELECT * from certificate WHERE user = $1 AND (active = $2 OR active = $3)"
	SQLFetchUserCertIds = "SELECT id from certificate WHERE user = $1"
	SQLCertUpdateActive = "UPDATE certificate SET active = $1 WHERE user = $2 AND id = $3;"
	SQLCertDeleteUsers  = "DELETE from certificate WHERE user = $1"
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
// speedups on the database.
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
	QueryUpdateCert, err = db.PrepareNamed(SQLUpdateCert)
	if err != nil {
		return err
	}
	QueryDeleteCert, err = db.Preparex(SQLDeleteCert)
	if err != nil {
		return err
	}

	// Other miscellaneous queries
	QueryFetchUserCerts, err = db.Preparex(SQLUpdateCert)
	if err != nil {
		return err
	}
	QueryFetchUserCertIds, err = db.Preparex(SQLFetchUserCerts)
	if err != nil {
		return err
	}
	QueryDeleteCert, err = db.Preparex(SQLDeleteCert)
	if err != nil {
		return err
	}
	QueryCertDeleteUsers, err = db.Preparex(SQLCertDeleteUsers)
	if err != nil {
		return err
	}

	return nil
}

// Given a UserExtended, insert a row into the database
// If the user struct contains certificates, insert
// the certificates in a transaction safe manner.
func DatabaseCreateUser(user *UserExtended) error {
	// Use a transaction as there might be multiple
	// queries if we are also creating certificates.
	// We want to avoid a situation where a client could
	// read a new user with only a partial list of certificates
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	createUserStmt := tx.Stmtx(QueryCreateUser)
	createCertStmt := tx.Stmtx(QueryCreateCert)

	// Insert the user
	res, err := createUserStmt.Exec(user)
	if err != nil {
		rollerr := tx.Rollback()
		if rollerr != nil {
			log.Println(rollerr)
		}
		return err
	}

	// Get the ID for the user
	lastId, err := res.LastInsertId()
	if err != nil {
		rollerr := tx.Rollback()
		if rollerr != nil {
			log.Println(rollerr)
		}
		return err
	}

	// If the User contains certificates, insert them as well
	if len(user.Certs) != 0 {
		for cert := range user.Certs {
			_, err := createCertStmt.Exec(cert)
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

	// Update the User.Id
	user.Id = strconv.Itoa(int(lastId))

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

	// Attach the cert IDs
	err = QueryFetchUserCertIds.Select(&user.Certs, userid)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	return user, nil
}

// Given a userID, get a UserExtended with the full certificate list
func DatabaseReadUserExtended(userid, showcerts string) (*UserExtended, error) {
	// Build the User struct
	user := new(UserExtended)
	err := QueryReadUser.Get(user, userid)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		} else {
			return nil, err
		}
	}

	// Attach the Certificates
	var ac1, ac2 bool
	if showcerts == ShowCertsActive {
		ac1, ac2 = true, true
	} else if showcerts == ShowCertsInactive {
		ac1, ac2 = false, false
	} else if showcerts == ShowCertsAll {
		ac1 = true
		ac2 = false
	} else {
		panic("Invalid showcerts option passed to DatabaseReadUserExtended")
	}
	err = QueryFetchUserCerts.Select(&user.Certs, userid, ac1, ac2)
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
	result, err := QueryDeleteUser.Exec(userid)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); affected == 0 || err != nil {
		return ErrNotFound
	}
	return nil
}
