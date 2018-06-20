	CREATE TABLE Users 
	(
		UserID INT(6) AUTO_INCREMENT PRIMARY KEY,
		Username VARCHAR(20) NOT NULL,
		Password VARCHAR(40) NOT NULL
	)

	CRETE TABLE Sessions
	(
		UserID INT(6) NOT NULL,
		SessionID VARCHAR(40) NOT NULL,	
		PRIMARY KEY (UserID),
		FOREIGN KEY (UserID) REFERENCES Users(UserID)
	) 


	CREATE TABLE PreSessions
	(
		UserID INT(6) NOT NULL,
		SessionToken VARCHAR(40) NOT NULL,	
		PRIMARY KEY (UserID),
		FOREIGN KEY (UserID) REFERENCES Users(UserID)
	) 




CREATE TRIGGER hashPassCI
BEFORE INSERT ON CRYPTO.PreSessions FOR EACH ROW
BEGIN
  -- A hashed password is 40 characters long.
  IF LENGTH(NEW.SessionToken) != 40 THEN
    SET NEW.SessionToken = SHA1(NEW.SessionToken,0);
  END IF;
END



