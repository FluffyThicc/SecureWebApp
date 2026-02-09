-- Run this against SecureWebAppDb_v2 if the migration didn't apply
-- Adds CurrentSessionToken and SessionIssuedAtUtc to AspNetUsers

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('AspNetUsers') AND name = 'CurrentSessionToken')
BEGIN
    ALTER TABLE AspNetUsers ADD CurrentSessionToken nvarchar(64) NULL;
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('AspNetUsers') AND name = 'SessionIssuedAtUtc')
BEGIN
    ALTER TABLE AspNetUsers ADD SessionIssuedAtUtc datetime2 NULL;
END
GO

-- Record in migration history so EF won't try to run the migration again
IF NOT EXISTS (SELECT 1 FROM __EFMigrationsHistory WHERE MigrationId = '20260204000000_AddSessionTokenForSingleActiveSession')
BEGIN
    INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion) 
    VALUES ('20260204000000_AddSessionTokenForSingleActiveSession', '9.0.0');
END
GO
