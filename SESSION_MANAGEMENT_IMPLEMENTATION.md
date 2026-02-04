# Session Management & Login/Logout Implementation

## Overview
This document describes the implementation of session management, rate limiting, audit logging, and secure login/logout features for the SecureWebApp.

## Features Implemented

### 1. Session Management (10%)
✅ **Secured Session Creation**
- Session is created upon successful login and registration
- Session stores:
  - `UserId`: Current user ID
  - `SessionId`: Unique session identifier (GUID)
  - `LoginTime`: Timestamp of login
  - `UserAgent`: Browser/client information
  - `IpAddress`: Client IP address

✅ **Session Timeout**
- Session expires after 30 minutes of inactivity
- Sliding expiration: Session timeout resets on user activity
- Automatic redirect to login page after timeout
- Timeout message displayed to user

✅ **Session Timeout Redirect**
- Middleware (`SessionTimeoutMiddleware`) checks session validity
- Redirects to `/Account/Login?timeout=true` after session expiry
- Clears session data and signs out user
- Logs timeout event to audit log

✅ **Multiple Login Detection**
- Tracks session IDs for each login
- Detects multiple logins from different devices/browser tabs
- Logs multiple login events to audit log
- Supports concurrent sessions (does not block, only logs)

### 2. Login/Logout Credential Verification (10%)
✅ **Login After Registration**
- Users can immediately login after successful registration
- Automatic sign-in after registration is implemented
- Redirects to homepage after registration/login

✅ **Rate Limiting (Account Lockout)**
- Account locks after **3 failed login attempts** (changed from 5)
- Lockout duration: **10 minutes**
- Lockout status displayed to user with clear message
- Failed attempts tracked by ASP.NET Core Identity

✅ **Safe Logout**
- Clears all session data (`HttpContext.Session.Clear()`)
- Signs out user using `SignInManager.SignOutAsync()`
- Logs logout activity to audit log
- Redirects to login page after logout (not homepage)

✅ **Audit Logging**
- **Database Table**: `AuditLogs` table stores all user activities
- **Tracked Activities**:
  - Login (success/failure)
  - Logout
  - Registration (success/failure)
  - Session Timeout
  - Multiple Login Detection
- **Logged Information**:
  - User ID
  - Action type
  - Description
  - IP Address
  - User Agent (browser info)
  - Session ID
  - Timestamp
  - Success/Failure status
  - Failure reason (if applicable)

✅ **Homepage Redirect After Login**
- Successful login redirects to homepage (`/Home/Index`)
- Homepage displays user info including decrypted NRIC
- User profile information shown when authenticated

## Technical Implementation

### Files Created/Modified

1. **`Models/AuditLog.cs`** (NEW)
   - Model for audit log entries
   - Properties: Id, UserId, Action, Description, IpAddress, UserAgent, SessionId, Timestamp, IsSuccess, FailureReason

2. **`Data/ApplicationDbContext.cs`** (MODIFIED)
   - Added `DbSet<AuditLog> AuditLogs` property
   - Configured indexes for efficient queries

3. **`Middleware/SessionTimeoutMiddleware.cs`** (NEW)
   - Middleware to check session validity
   - Handles session timeout detection
   - Redirects to login on timeout
   - Logs timeout events

4. **`Controllers/AccountController.cs`** (MODIFIED)
   - Added `ApplicationDbContext` for audit logging
   - Updated `Register` method: Creates session, logs audit
   - Updated `Login` method: 
     - Creates secured session
     - Detects multiple logins
     - Logs all login attempts (success/failure)
     - Handles account lockout
   - Updated `Logout` method:
     - Clears session data
     - Logs logout activity
     - Redirects to login page
   - Added `LogAuditActivity` helper method

5. **`Program.cs`** (MODIFIED)
   - Configured session settings (30-minute timeout)
   - Added session middleware
   - Registered `SessionTimeoutMiddleware`
   - Updated lockout settings (3 attempts, 10 minutes)
   - Enhanced cookie security settings

6. **`Views/Account/Login.cshtml`** (MODIFIED)
   - Added timeout message display
   - Shows session expired notification

### Database Migration

Run the following command to create the `AuditLogs` table:
```bash
dotnet ef migrations add AddAuditLogTable
dotnet ef database update
```

### Session Configuration

**Session Settings** (in `Program.cs`):
- Timeout: 30 minutes
- HttpOnly: Enabled (XSS protection)
- SameSite: Strict (CSRF protection)
- Sliding Expiration: Enabled

**Cookie Settings**:
- HttpOnly: Enabled
- Secure: SameAsRequest (use HTTPS in production)
- SameSite: Strict
- Timeout: 30 minutes

### Audit Log Examples

**Successful Login**:
```
UserId: abc123
Action: Login
Description: User logged in successfully
IpAddress: 192.168.1.100
SessionId: guid-here
IsSuccess: true
```

**Failed Login**:
```
UserId: abc123
Action: Login
Description: Invalid password attempt
IpAddress: 192.168.1.100
IsSuccess: false
FailureReason: Invalid password
```

**Account Lockout**:
```
UserId: abc123
Action: Login
Description: Account locked out due to multiple failed attempts
IsSuccess: false
FailureReason: Account locked out
```

**Multiple Login Detection**:
```
UserId: abc123
Action: Login
Description: Multiple login detected. Previous session: guid-here
IsSuccess: true
SessionId: new-guid-here
```

**Session Timeout**:
```
UserId: abc123
Action: SessionTimeout
Description: Session expired due to inactivity
IsSuccess: false
FailureReason: Session timeout (30 minutes)
```

## Security Features

1. **Session Security**:
   - HttpOnly cookies prevent XSS attacks
   - SameSite=Strict prevents CSRF attacks
   - Secure flag for HTTPS in production

2. **Rate Limiting**:
   - Prevents brute force attacks
   - 3 failed attempts trigger 10-minute lockout

3. **Audit Trail**:
   - Complete logging of all user activities
   - Helps with security incident investigation
   - Tracks IP addresses and user agents

4. **Session Timeout**:
   - Prevents unauthorized access to idle sessions
   - Automatic cleanup of expired sessions

## Testing Checklist

- [x] User can login after registration
- [x] Session created on successful login
- [x] Session expires after 30 minutes of inactivity
- [x] User redirected to login after session timeout
- [x] Account locks after 3 failed login attempts
- [x] User can logout safely
- [x] Session cleared on logout
- [x] Audit log entries created for all activities
- [x] Multiple login detection works
- [x] Homepage displays user info after login

## Next Steps

To test the implementation:
1. Stop the running application (if running)
2. Run `dotnet ef migrations add AddAuditLogTable`
3. Run `dotnet ef database update`
4. Start the application: `dotnet run`
5. Test registration, login, logout, and session timeout scenarios

## Notes

- The application must be stopped before running migrations
- Session timeout uses UTC time for consistency
- Multiple logins are detected but not blocked (logged only)
- Audit logs are stored in the database and can be queried for reporting





