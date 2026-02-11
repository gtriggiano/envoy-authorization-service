IF DB_ID('security') IS NULL
BEGIN
    CREATE DATABASE security;
END
GO

USE security;
GO

IF OBJECT_ID('dbo.trusted_ips', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.trusted_ips (
        ip VARCHAR(64) PRIMARY KEY
    );
END
GO

MERGE dbo.trusted_ips AS target
USING (VALUES
    ('203.0.113.10'),
    ('198.51.100.77')
) AS source (ip)
ON target.ip = source.ip
WHEN NOT MATCHED THEN
    INSERT (ip) VALUES (source.ip);
GO
