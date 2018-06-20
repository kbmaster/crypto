CREATE TABLE Users(
  UserID int(6) NOT NULL,
  Username varchar(20)  NOT NULL,
  Password varchar(40)  NOT NULL,
  PRIMARY KEY (UserID)
)


CREATE TABLE Sessions (
  UserID int(6) NOT NULL,
  SessionID varchar(40) COLLATE NOT NULL,
  PRIMARY KEY (SessionID),
  KEY UserID (UserID),
  CONSTRAINT `Sessions_ibfk_1` FOREIGN KEY (UserID) REFERENCES Users(UserID)
)


