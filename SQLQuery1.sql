USE master;
GO

-- Koppla fr�n och ta bort databasen om den existerar
IF EXISTS (SELECT * FROM sys.databases WHERE name = 'HederligeHarrysBilar')
BEGIN
    ALTER DATABASE HederligeHarrysBilar
    SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE HederligeHarrysBilar;
    PRINT 'Databasen "HederligeHarrysBilar" har tagits bort.';
END;

-- Skapa databasen
CREATE DATABASE HederligeHarrysBilar;
PRINT 'Databasen "HederligeHarrysBilar" har skapats.';
GO

-- V�xla till databasen
USE HederligeHarrysBilar;
GO

-- Ta bort tabellerna om de redan existerar
IF OBJECT_ID('Users', 'U') IS NOT NULL
BEGIN
    DROP TABLE Users;
END;
GO

IF OBJECT_ID('LoginAttempts', 'U') IS NOT NULL
BEGIN
    DROP TABLE LoginAttempts;
END;
GO

-- Skapa tabellen Users
CREATE TABLE Users (
    UserID INT IDENTITY(1,1) PRIMARY KEY,
    FirstName NVARCHAR(50) NOT NULL,
    LastName NVARCHAR(50) NOT NULL,
    EmailAddress NVARCHAR(255) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(128) NOT NULL,
	Salt NVARCHAR(50) NOT NULL,
    Address NVARCHAR(100) NOT NULL,
    PostalCode NVARCHAR(20) NOT NULL,
    City NVARCHAR(50) NOT NULL,
    Country NVARCHAR(50) NOT NULL,
    PhoneNumber NVARCHAR(20) NOT NULL,
    IsVerified BIT NOT NULL DEFAULT 0,
    IsLockedOut BIT NOT NULL DEFAULT 0,
    Role NVARCHAR(20) NOT NULL DEFAULT 'Customer',
    PasswordResetCode NVARCHAR(255) NULL,
    PasswordResetExpiry DATETIME NULL,
    CreatedAt DATETIME NOT NULL DEFAULT GETDATE(),
    UpdatedAt DATETIME NOT NULL DEFAULT GETDATE()
);

GO

-- Skapa tabellen LoginAttempts
CREATE TABLE LoginAttempts (
    AttemptID INT IDENTITY(1,1) PRIMARY KEY,
    UserID INT NULL,
    Email NVARCHAR(255) NULL,
    IPAddress NVARCHAR(50) NOT NULL,
    AttemptDate DATETIME NOT NULL DEFAULT GETDATE(),
    Success BIT NOT NULL,
    FOREIGN KEY (UserID) REFERENCES Users(UserID)
);

-- Index f�r snabbare s�kning p� e-postadress
CREATE INDEX IDX_Email ON Users (EmailAddress);

-- Index f�r snabbare s�kning p� IP-adress i LoginAttempts
CREATE INDEX IDX_IP ON LoginAttempts (IPAddress);


GO
--Registrering av anv�ndare

CREATE OR ALTER PROCEDURE RegisterUser
    @FirstName NVARCHAR(50),
    @LastName NVARCHAR(50),
    @EmailAddress NVARCHAR(255),
    @Password NVARCHAR(50),
    @Address NVARCHAR(255),
    @PostalCode NVARCHAR(20),
    @City NVARCHAR(50),
    @Country NVARCHAR(50),
    @PhoneNumber NVARCHAR(20)
AS
BEGIN
    -- Kontrollera om e-postadressen redan finns
    IF EXISTS (SELECT 1 FROM Users WHERE EmailAddress = @EmailAddress)
    BEGIN
        PRINT 'E-postadressen anv�nds redan.';
        RETURN;
    END

    -- Kontrollera l�senordets styrka
    IF @Password NOT LIKE '%[A-Z]%' OR       -- Minst en stor bokstav
       @Password NOT LIKE '%[a-z]%' OR       -- Minst en liten bokstav
       @Password NOT LIKE '%[0-9]%' OR       -- Minst en siffra
       @Password NOT LIKE '%[^a-zA-Z0-9]%' OR -- Minst ett specialtecken
       LEN(@Password) < 8                   -- Minsta l�ngd
    BEGIN
        PRINT 'L�senordet uppfyller inte kraven.';
        RETURN;
    END

    -- ?? Generera ett slumpm�ssigt salt
    DECLARE @Salt NVARCHAR(255) = CONVERT(NVARCHAR(255), NEWID());

    -- ?? Kombinera l�senord + salt och hash med SHA2_256
    DECLARE @PasswordWithSalt NVARCHAR(255) = @Password + @Salt;
    DECLARE @PasswordHash NVARCHAR(128) = CONVERT(NVARCHAR(255), HASHBYTES('SHA2_256', @PasswordWithSalt), 1);

    -- ?? L�gg till anv�ndaren i databasen
    INSERT INTO Users (FirstName, LastName, EmailAddress, Salt, PasswordHash, Address, PostalCode, City, Country, PhoneNumber, Role)
    VALUES (@FirstName, @LastName, @EmailAddress, @Salt, @PasswordHash, @Address, @PostalCode, @City, @Country, @PhoneNumber, 'Customer');

    PRINT 'Anv�ndaren har registrerats!';
END;
GO


--Uppdatering av roll (endast av Admins)

CREATE OR ALTER PROCEDURE UpdateUserRole
    @EmailAddress NVARCHAR(255),
    @NewRole NVARCHAR(20)
AS
BEGIN
    -- Kontrollera om anv�ndaren finns
    IF NOT EXISTS (SELECT 1 FROM Users WHERE EmailAddress = @EmailAddress)
    BEGIN
        PRINT 'Anv�ndaren hittades inte.';
        RETURN;
    END

    -- Kontrollera om rollen �r giltig (Customer eller Admin)
    IF @NewRole NOT IN ('Customer', 'Admin')
    BEGIN
        PRINT 'Ogiltig roll. Till�tna roller �r Customer eller Admin.';
        RETURN;
    END

    -- Uppdatera anv�ndarens roll
    UPDATE Users
    SET Role = @NewRole, UpdatedAt = GETDATE()
    WHERE EmailAddress = @EmailAddress;

    PRINT 'Anv�ndarens roll har uppdaterats!';
END;


--2 Procedur f�r att skicka verifieringskod

GO
CREATE OR ALTER PROCEDURE VerifyAccount
    @EmailAddress NVARCHAR(255)
AS
BEGIN
    -- Kontrollera om anv�ndaren finns
    IF NOT EXISTS (SELECT 1 FROM Users WHERE EmailAddress = @EmailAddress)
    BEGIN
        PRINT 'E-postadressen hittades inte.';
        RETURN;
    END

    -- Uppdatera IsVerified till 1
    UPDATE Users
    SET IsVerified = 1
    WHERE EmailAddress = @EmailAddress;

    PRINT 'Kontot har verifierats.';
END;


--L�senords�terst�llning
GO
CREATE OR ALTER PROCEDURE ForgotPassword
    @EmailAddress NVARCHAR(255)
AS
BEGIN
    -- Kontrollera om anv�ndaren finns
    IF NOT EXISTS (SELECT 1 FROM Users WHERE EmailAddress = @EmailAddress)
    BEGIN
        PRINT 'E-postadressen hittades inte.';
        RETURN;
    END

    -- Skapa en unik reset-kod och s�tt giltighetstiden
    DECLARE @ResetCode NVARCHAR(255) = NEWID();
    DECLARE @Expiry DATETIME = DATEADD(HOUR, 24, GETDATE());

    -- Uppdatera anv�ndarens reset-kod och giltighetstid
    UPDATE Users
    SET PasswordResetCode = @ResetCode, PasswordResetExpiry = @Expiry
    WHERE EmailAddress = @EmailAddress;

    PRINT 'En �terst�llningskod har skickats till anv�ndaren.';
END;


--L�gga in nytt gl�mt l�senord
GO
CREATE OR ALTER PROCEDURE SetForgottenPassword
    @Email NVARCHAR(255),
    @NewPassword NVARCHAR(255),
    @ResetCode NVARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;

    -- Check if the reset code exists and is not expired
    DECLARE @UserID INT;
    SELECT @UserID = UserID
    FROM Users
    WHERE PasswordResetCode = @ResetCode
      AND PasswordResetExpiry >= GETDATE();

    IF @UserID IS NULL
    BEGIN
        RAISERROR('Invalid or expired reset code.', 16, 1);
        RETURN;
    END

    -- Update the user's password
    UPDATE Users
    SET PasswordHash = @NewPassword
    WHERE UserID = @UserID;
	
-- Clear the reset code and expiry from the Users table
UPDATE Users
SET PasswordResetCode = NULL,
    PasswordResetExpiry = NULL
WHERE UserID = @UserID;

    PRINT 'Password successfully updated.';
END;

--Logga in f�rs�k och hantering av l�sta konton

GO
CREATE OR ALTER PROCEDURE TryLogin
    @EmailAddress NVARCHAR(255),
    @Password NVARCHAR(50),
    @IPAddress NVARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;

    -- Skapa tempor�r tabell om den inte finns
    IF OBJECT_ID('tempdb..##TempLoginLogs') IS NULL
    BEGIN
        CREATE TABLE ##TempLoginLogs (
            AttemptID INT IDENTITY(1,1),
            Email NVARCHAR(255),
            IPAddress NVARCHAR(50),
            AttemptDate DATETIME DEFAULT GETDATE(),
            Success BIT
        );
    END;

    -- H�mta anv�ndaren
    DECLARE @UserID INT, @Salt NVARCHAR(50), @PasswordHash NVARCHAR(128), @IsLockedOut BIT;
    SELECT @UserID = UserID, @Salt = Salt, @PasswordHash = PasswordHash, @IsLockedOut = IsLockedOut
    FROM Users WHERE EmailAddress = @EmailAddress;

    -- Kontrollera om anv�ndaren finns
    IF @UserID IS NULL
    BEGIN
        INSERT INTO LoginAttempts (Email, IPAddress, Success, AttemptDate)
        VALUES (@EmailAddress, @IPAddress, 0, GETDATE());

        INSERT INTO ##TempLoginLogs (Email, IPAddress, Success)
        VALUES (@EmailAddress, @IPAddress, 0);

        PRINT 'Fel e-postadress eller l�senord.';
        RETURN;
    END;

    -- Kontrollera om kontot �r l�st
    IF @IsLockedOut = 1
    BEGIN
        PRINT 'Kontot �r l�st. Kontakta support.';
        RETURN;
    END;

    -- Ber�kna hash av det angivna l�senordet + salt
    DECLARE @InputHash NVARCHAR(MAX) = CONVERT(NVARCHAR(MAX), HASHBYTES('SHA2_256', @Password + @Salt), 1);

    -- J�mf�r den ber�knade hashen med lagrad hash
    IF @InputHash = @PasswordHash
    BEGIN
        -- Logga lyckat f�rs�k
        INSERT INTO LoginAttempts (UserID, Email, IPAddress, Success, AttemptDate)
        VALUES (@UserID, @EmailAddress, @IPAddress, 1, GETDATE());

        -- Spara ocks� i den tempor�ra tabellen
        INSERT INTO ##TempLoginLogs (Email, IPAddress, Success)
        VALUES (@EmailAddress, @IPAddress, 1);

        PRINT 'Inloggningen lyckades!';
    END
    ELSE
    BEGIN
        -- Logga misslyckat f�rs�k
        INSERT INTO LoginAttempts (UserID, Email, IPAddress, Success, AttemptDate)
        VALUES (@UserID, @EmailAddress, @IPAddress, 0, GETDATE());

        INSERT INTO ##TempLoginLogs (Email, IPAddress, Success)
        VALUES (@EmailAddress, @IPAddress, 0);

        -- Kontrollera misslyckade f�rs�k inom de senaste 15 minuterna
        DECLARE @FailedAttempts INT;
        SELECT @FailedAttempts = COUNT(*) 
        FROM LoginAttempts
        WHERE UserID = @UserID 
        AND Success = 0 
        AND AttemptDate > DATEADD(MINUTE, -15, GETDATE());

        -- Om 3 misslyckade f�rs�k blir kontot l�st
        IF @FailedAttempts >= 3
        BEGIN
            UPDATE Users SET IsLockedOut = 1 WHERE UserID = @UserID;
            PRINT 'Kontot har l�sts efter tre misslyckade f�rs�k. V�nta 15 minuter eller kontakta support.';
        END
        ELSE
        BEGIN
            PRINT 'Inloggningen misslyckades. F�rs�k igen.';
        END
    END;
END;
GO






CREATE OR ALTER PROCEDURE LockUnlockUser
    @EmailAddress NVARCHAR(255),
    @Action NVARCHAR(10) -- 'LOCK' eller 'UNLOCK'
AS
BEGIN
    IF @Action = 'LOCK'
    BEGIN
        UPDATE Users
        SET IsLockedOut = 1
        WHERE EmailAddress = @EmailAddress;

        PRINT 'Anv�ndaren har blivit l�st.';
    END
    ELSE IF @Action = 'UNLOCK'
    BEGIN
        UPDATE Users
        SET IsLockedOut = 0
        WHERE EmailAddress = @EmailAddress;

        PRINT 'Anv�ndaren har blivit uppl�st.';
    END
    ELSE
    BEGIN
        PRINT 'Ogiltig �tg�rd. Anv�nd LOCK eller UNLOCK.';
    END;
END;


--Rapporter (Views med CTE)
--Rapport: Senaste lyckade och misslyckade inloggningar


-- Skapa eller ers�tt VIEW

GO
CREATE OR ALTER VIEW UserLoginReport AS
WITH LatestLogins AS (
    SELECT 
        UserID,
        MAX(CASE WHEN Success = 1 THEN AttemptDate END) AS LastSuccessfulLogin,
        MAX(CASE WHEN Success = 0 THEN AttemptDate END) AS LastFailedLogin
    FROM LoginAttempts
    GROUP BY UserID
)
SELECT 
    u.EmailAddress,
    u.FirstName,
    u.LastName,
    ll.LastSuccessfulLogin,
    ll.LastFailedLogin
FROM Users u
LEFT JOIN LatestLogins ll ON u.UserID = ll.UserID;
GO




--Rapport: Antal lyckade och misslyckade f�rs�k per IP-adress
GO
CREATE OR ALTER VIEW LoginAttemptsPerIP AS
WITH AttemptSummary AS (
    SELECT 
        IPAddress,
        COUNT(*) OVER (PARTITION BY IPAddress) AS TotalAttempts,
        SUM(CASE WHEN Success = 1 THEN 1 ELSE 0 END) OVER (PARTITION BY IPAddress) AS SuccessfulAttempts,
        SUM(CASE WHEN Success = 0 THEN 1 ELSE 0 END) OVER (PARTITION BY IPAddress) AS FailedAttempts,
        AVG(CASE WHEN Success = 1 THEN 1.0 ELSE 0 END) OVER (PARTITION BY IPAddress) AS AvgSuccessfulAttempts,
        AttemptDate
    FROM LoginAttempts
)
SELECT 
    IPAddress,
    TotalAttempts,
    SuccessfulAttempts,
    FailedAttempts,
    AvgSuccessfulAttempts,
    AttemptDate
FROM AttemptSummary
GO

DECLARE @Run BIT = 0;  -- S�tt till 1 f�r att k�ra fr�gor och svar, 0 f�r att hoppa �ver.
DECLARE @Fr�ga1 BIT = 0;
DECLARE @Fr�ga2 BIT = 0;
DECLARE @Fr�ga3 BIT = 0;
DECLARE @Fr�ga4 BIT = 0;
DECLARE @Fr�ga5 BIT = 0;
DECLARE @Fr�ga6 BIT = 0;
DECLARE @Fr�ga7 BIT = 0;
DECLARE @Fr�ga8 BIT = 0;
DECLARE @Fr�ga9 BIT = 0;
DECLARE @VGFr�ga1 BIT = 0;
DECLARE @VGFr�ga2 BIT = 0;
DECLARE @VGFr�ga3 BIT = 0;
DECLARE @VGFr�ga4 BIT = 0;
DECLARE @VGFr�ga5 BIT = 0;


IF @Run = 1
BEGIN
    PRINT 'K�r Fr�gorna och Svaren.';



-----------------------------------------


-- 1. Registera dig som ny anv�ndare

 IF @Fr�ga1 = 0
    BEGIN
        EXEC RegisterUser 
            @FirstName = 'FirstName',
            @LastName = 'LastName',
            @EmailAddress = 'account@hotmail.com',
            @Password = 'account123!',
            @Address = 'NackademinGatan 5',
            @PostalCode = '12345',
            @City = 'Stockholm',
            @Country = 'Sweden',
            @PhoneNumber = '0701234567';
    END


-- 2. Verifiera sitt konto

IF @Fr�ga2 = 0
BEGIN
EXEC VerifyAccount @EmailAddress = 'account@hotmail.com';
END

-- Testa Logga in:

EXEC TryLogin 
    @EmailAddress = 'account@hotmail.com',
    @Password = 'account123!',
    @IPAddress = '192.168.0.2'

-- 3. Gl�mt l�senord

 IF @Fr�ga3 = 0
    BEGIN
EXEC ForgotPassword @EmailAddress = 'account@hotmail.com';
--(Skickas kod till column 'PassWordResetCode')
END

-- Skriv in nytt l�senord

 IF @Fr�ga3 = 0
    BEGIN
EXEC SetForgottenPassword
    @Email = 'account@hotmail.com',
    @NewPassword = 'account12345!',
    @ResetCode = 'XXXXX-XXXXX-XXXXX'
	END

	--SELECT * FROM Users

-- 4.Customer - default, �ndra roll till Admin;
 IF @Fr�ga4 = 0
    BEGIN
EXEC UpdateUserRole 
     @EmailAddress = 'account@hotmail.com', 
	 @NewRole = 'Admin'
	 END

-- 5.L�sa en anv�ndare;

 IF @Fr�ga5 = 0
    BEGIN
EXEC LockUnlockUser 
    @EmailAddress = 'account@hotmail.com',
    @Action = 'LOCK';
	END

-- 6. Inloggningsf�rs�k i tabell (IP-address,email,date and time, success)

 IF @Fr�ga6 = 0
    BEGIN
SELECT *
FROM LoginAttempts
END

-- 7. Senaste lyckade/misslyckade inloggning (Datum/tid), VIEW

 IF @Fr�ga7 = 0
    BEGIN
SELECT *
FROM UserLoginReport
ORDER BY LastSuccessfulLogin DESC, LastFailedLogin DESC;
END

-- 8. Rapport inloggningsf�rs�k lyckades/misslyckades per ip-adress.
--(visa antal f�rs�k total,lyckade,misslyckade,genomsnittliga lyckade f�rs�k)

 IF @Fr�ga8 = 0
    BEGIN
SELECT *
FROM LoginAttemptsPerIP
ORDER BY TotalAttempts DESC;
END

-- 9. Manuellt l�gg in v�rden i user- och logg-tabellen

 IF @Fr�ga9 = 0
    BEGIN
INSERT INTO LoginAttempts (UserID, Email, IPAddress, Success)
VALUES 
(1, 'account@hotmail.com', '192.168.0.1', 1),
(1, 'account@hotmail.com', '192.168.0.2', 0),
(1, 'account@hotmail.com', '192.168.0.1', 0);


END


-- 10. Ren och l�sbar kod som f�ljer best practices. (OK)


-- 11. Scriptet ska kunna exekveras UTAN FEL. 
--Testa noggrant innan ni l�mnar in att inga run time errors eller logiska fel intr�ffar. (OK)

----------------------------


--F�R V�L GODK�NT
--1. Om man misslyckats med att logga in tre g�nger de senaste 15 minuterna kommer man inte in oavsett om man skriver r�tt l�senord eller inte. (OK)

 IF @VGFr�ga1 = 0
    BEGIN
EXEC TryLogin @EmailAddress = 'account@hotmail.com', @Password = 'Fel123!', @IPAddress = '192.168.0.2';
EXEC TryLogin @EmailAddress = 'account@hotmail.com', @Password = 'Fel123!', @IPAddress = '192.168.0.2';
EXEC TryLogin @EmailAddress = 'account@hotmail.com', @Password = 'Fel123!', @IPAddress = '192.168.0.2';
END;



--2. Skapa stored procedures f�r trylogin(email,password. ipaddress) och denna ska kontrollera alla saker ovan enl. G och VG krav SAMT returnera l�mpliga felkoder ifall det inte gick. 
--Kom ih�g att lagra i loggtabellen. Loggar ska �ven sparas i en tempor�r tabell i samma SP, som ni ex. kan anv�nda f�r testning.
--(OK)

IF @VGFr�ga2 = 0
    BEGIN
SELECT * FROM ##TempLoginLogs
END;

--3. Skapa stored procedure f�r forgotpassword(email) och denna ska skapa och lagra password koden (token). Eventuella felkoder ska returneras.

 IF @VGFr�ga3 = 0
BEGIN
EXEC ForgotPassword @EmailAddress = 'account@hotmail.com';
END;


--4. G�r stored procedure f�r setforgottenpassword(email,password,token). Kolla s� r�tt token, r�tt tid (ej expired). Eventuella felkoder ska returneras.

 IF @VGFr�ga4 = 0
BEGIN
EXEC SetForgottenPassword 
    @Email = 'account@hotmail.com',
    @NewPassword = 'NyttL�senord123!',
    @ResetCode = 'XXXXX-XXXXX-XXXXX';
END;

ELSE BEGIN
    PRINT 'Fr�gorna och svaren k�rs inte.';
END;
END

--5. Demonstrera anv�ndandet av era SP. Dessa ska returnera resultat som ni visar:
--Samtliga SP och svar p� fr�gorna finns uppe i ordning enligt inl�mningsuppgiften








--6. Ni ska konstruera scriptet och rapporterna med optimering i �tanke. Detta ska tydligt redovisas i er dokumentation. (OK)

--Ni ska redovisa hur ni har arbetat med optimering, hur systemet skulle kunna f�rb�ttras i framtiden i relation till optimering, 

--vad man kan g�ra f�r att testa prestandan och ev. annat som ni tycker �r relevant.  
--(OK)
