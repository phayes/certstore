CREATE TABLE certstore_user (
  id SERIAL PRIMARY KEY, 
  name TEXT,
  email varchar(254)
);

-- email addresses should be stored case-sensitive, but they should be queried case-insensitive
CREATE INDEX ON certstore_user (lower(email));

CREATE TABLE certstore_cert (
  id CHAR(64) NOT NULL, 
  userid INT NOT NULL REFERENCES certstore_user(id), 
  active BOOLEAN NOT NULL, 
  cert TEXT NOT NULL,
  key TEXT  NOT NULL,
  PRIMARY KEY(id, userid),
  UNIQUE (id, userid)
);

CREATE INDEX ON certstore_cert (userid, active);