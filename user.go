package main

type User struct {
	Id    string             `json:"id"`
	Name  string             `json:"name"`
	Email string             `json:"email"`
	Certs []*CertificateData `json:"certs"`
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
