package main

import (
	"errors"
	"regexp"
	"strconv"
	"unicode/utf8"
)

var (
	ErrInvalidUserId    = errors.New("Invalid User. The User ID is malformed.")
	ErrInvalidUserName  = errors.New("Invalid User. The User Name is too long.")
	ErrInvalidUserEmail = errors.New("Invalid User. The User email is malformed.")

	// Proper regex for case sensitive email address. From https://github.com/asaskevich/govalidator.
	// TODO: Confirm that this works with IDN hostnames.
	RegExpEmail = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)

type User struct {
	Id    string             `json:"id"`
	Name  string             `json:"name"`
	Email string             `json:"email"`
	Certs []*CertificateData `json:"certs"`
}

// Validate that the Id is numeric, the name isn't too long, and the email address is valid
// Also validate all attached Certificates and normalizes them
func (u *User) ValidateNormalize() error {
	// Verify the userid is numeric and postive (if specified)
	if u.Id != "" {
		if checkid, err := strconv.Atoi(u.Id); err != nil || checkid <= 0 {
			return ErrInvalidUserId
		}
	}

	// Verify the name is not longer than 746 characters
	// The longeset name in the world thus far is that of Hubert Blaine Wolfeschlegelsteinhausenbergerdorff... with 746 characters.
	// TODO: Normalize name (trim)
	if utf8.RuneCountInString(u.Name) > 746 {
		return ErrInvalidUserName
	}

	// Verify the email address
	// TOOD: Normalize email address (trim and lowcase the domain)
	if !RegExpEmail.MatchString(u.Email) {
		return ErrInvalidUserEmail
	}

	// Verify and Normalize CertificateData
	if len(u.Certs) > 0 {
		for i, certData := range u.Certs {
			cert, err := NewCertificateFromData(certData)
			if err != nil {
				return err
			}
			u.Certs[i] = cert.GetData()
		}
	}

	// All is well
	return nil
}

// Get a slice of Certificate structs for this User
func (u *User) GetCerts() ([]*Certificate, error) {
	numcerts := len(u.Certs)
	if numcerts == 0 {
		return nil, nil
	}
	certs := make([]*Certificate, numcerts, numcerts)
	for i, certData := range u.Certs {
		var err error
		certs[i], err = NewCertificateFromData(certData)
		if err != nil {
			return certs, err
		}
	}
	return certs, nil
}
