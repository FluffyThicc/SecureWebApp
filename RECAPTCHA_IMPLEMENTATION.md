# Google reCAPTCHA v3 Implementation Guide

## Overview
This document describes the implementation of Google reCAPTCHA v3 for anti-bot protection on the registration and login forms.

## Features Implemented
✅ **reCAPTCHA v3 Integration**
- Server-side token verification
- Client-side token generation on form submission
- Score-based bot detection (default threshold: 0.5)
- Logging of verification results for monitoring

## How reCAPTCHA v3 Works
1. **Client Side**: When a form is submitted, reCAPTCHA executes in the background and generates a token
2. **Server Side**: The token is sent to Google's API for verification
3. **Verification**: Google returns a score (0.0 = bot, 1.0 = human) and success status
4. **Decision**: Based on the score threshold, the request is accepted or rejected

## Security Note
✅ **All sensitive keys are now stored in `.env` file** which is gitignored. Never commit `.env` to version control!

## Configuration

### Step 1: Get reCAPTCHA Keys from Google
1. Go to [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
2. Click "Create" to create a new site
3. Select **reCAPTCHA v3**
4. Add your domain (e.g., `localhost` for development)
5. Accept the terms and submit
6. Copy the **Site Key** and **Secret Key**

### Step 2: Configure Environment Variables
Create a `.env` file in the project root (copy from `.env.example`):

```bash
# Copy the example file
cp .env.example .env
```

Then edit `.env` and add your keys:

```env
RECAPTCHA_SITE_KEY=your_actual_site_key_here
RECAPTCHA_SECRET_KEY=your_actual_secret_key_here
RECAPTCHA_SCORE_THRESHOLD=0.5
```

**Important**: 
- The `.env` file is already added to `.gitignore` - **never commit it to version control**
- `RECAPTCHA_SCORE_THRESHOLD`: Score between 0.0 and 1.0 (default: 0.5)
  - **0.5-1.0**: Typical threshold (higher = stricter)
  - **0.0-0.5**: More lenient (may allow some bots)
  - Adjust based on your needs and false positive rates

**Note**: The application will automatically load the `.env` file on startup. If the `.env` file doesn't exist, the application will fall back to `appsettings.json` configuration (which doesn't contain the actual keys for security).

## Files Created/Modified

### 1. **`Services/RecaptchaService.cs`** (NEW)
- Service for verifying reCAPTCHA tokens
- Makes HTTP POST request to Google's verification API
- Returns boolean indicating if verification passed
- Logs verification results and scores

**Key Methods**:
- `VerifyTokenAsync()`: Verifies token with Google's API
- `GetSiteKey()`: Returns the site key from configuration

### 2. **`Controllers/AccountController.cs`** (MODIFIED)
- Added `RecaptchaService` dependency injection
- Updated `Register` (GET): Passes site key to view
- Updated `Register` (POST): Verifies reCAPTCHA token before processing
- Updated `Login` (GET): Passes site key to view
- Updated `Login` (POST): Verifies reCAPTCHA token before processing

**Verification Logic**:
- Extracts token from `g-recaptcha-response` form field
- Calls `RecaptchaService.VerifyTokenAsync()`
- If verification fails:
  - Adds error to ModelState
  - Logs audit entry
  - Returns to form with error message

### 3. **`Program.cs`** (MODIFIED)
- Registered `RecaptchaService` with HttpClient
- Added as scoped service

### 4. **`Views/Account/Register.cshtml`** (MODIFIED)
- Added reCAPTCHA v3 script tag
- Added JavaScript to execute reCAPTCHA on form submit
- Token is automatically included in form submission

### 5. **`Views/Account/Login.cshtml`** (MODIFIED)
- Added reCAPTCHA v3 script tag
- Added JavaScript to execute reCAPTCHA on form submit
- Token is automatically included in form submission

### 6. **`.env.example`** (NEW)
- Template file with example environment variables
- Copy to `.env` and fill in your actual keys
- `.env` file is gitignored for security

### 7. **`.gitignore`** (MODIFIED)
- Added `.env` and related environment files to gitignore

### 8. **`appsettings.json`** and **`appsettings.Development.json`** (MODIFIED)
- Removed actual keys (now stored in `.env` file)
- Added comment indicating keys are loaded from environment variables

## Implementation Details

### Client-Side Flow
```javascript
1. User fills form and clicks submit
2. Form submission is intercepted (preventDefault)
3. grecaptcha.execute() is called with site key and action
4. Token is received from Google
5. Token is added as hidden field: <input name="g-recaptcha-response" value="token">
6. Form is submitted with token included
```

### Server-Side Flow
```
1. Controller receives form submission
2. Extracts token from Request.Form["g-recaptcha-response"]
3. Calls RecaptchaService.VerifyTokenAsync(token, ipAddress)
4. Service makes POST to Google API with secret key
5. Google responds with verification result and score
6. Service checks if score >= threshold
7. Controller accepts/rejects based on result
```

## Security Features

1. **Score-Based Detection**: Uses risk score (0.0-1.0) instead of binary pass/fail
2. **IP Tracking**: Includes client IP address in verification request
3. **Action Tracking**: Different actions for login vs register (monitoring)
4. **Audit Logging**: Failed verifications are logged to audit log
5. **Graceful Degradation**: If keys not configured, forms still work (logs warning)

## Testing

### Test with Valid Keys
1. Configure actual Site Key and Secret Key
2. Submit registration/login forms
3. Check logs for verification results
4. Verify successful submissions are processed

### Test Score Threshold
1. Set `ScoreThreshold` to 0.9 (very strict)
2. Some legitimate users may be blocked
3. Adjust threshold based on false positive rate
4. Typical production threshold: 0.5-0.7

### Test Without Keys (Development)
- Forms still work but reCAPTCHA is bypassed
- Warning logged: "reCAPTCHA Secret Key is not configured"
- Useful for local development without Google API

## Monitoring

### Check Audit Logs
```sql
SELECT * FROM AuditLogs 
WHERE Action = 'Register' OR Action = 'Login'
ORDER BY Timestamp DESC
```

### Check Application Logs
Look for log entries with:
- "reCAPTCHA verification - Success: true/false, Score: X"
- "reCAPTCHA verification failed"

### Google reCAPTCHA Analytics
- Login to [reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
- View analytics dashboard
- Monitor request volume, score distribution, and abuse reports

## Troubleshooting

### Issue: "reCAPTCHA verification failed"
**Possible Causes**:
1. Invalid Secret Key
2. Token expired (tokens are single-use)
3. Domain mismatch (Site Key registered for different domain)
4. Score below threshold
5. `.env` file not loaded properly

**Solution**:
- Verify keys in `.env` file (not appsettings.json)
- Ensure `.env` file exists in project root
- Check domain in reCAPTCHA console
- Lower RECAPTCHA_SCORE_THRESHOLD if too strict
- Check application logs for details
- Verify DotNetEnv package is installed

### Issue: Token Not Generated
**Possible Causes**:
1. Site Key not configured
2. reCAPTCHA script not loaded
3. JavaScript errors

**Solution**:
- Verify RECAPTCHA_SITE_KEY in `.env` file
- Ensure `.env` file is in project root
- Check browser console for errors
- Ensure script tag is in HTML
- Check network tab for script loading

### Issue: Forms Submit Without Verification
**Possible Causes**:
1. Keys not configured (graceful degradation)
2. JavaScript disabled
3. reCAPTCHA service not registered

**Solution**:
- Verify service registration in Program.cs
- Ensure keys are configured
- Check browser JavaScript is enabled

## Best Practices

1. **Use HTTPS in Production**: reCAPTCHA requires HTTPS for production
2. **Monitor Scores**: Adjust threshold based on false positive rates
3. **Keep Keys Secret**: Never commit secret keys to version control
4. **Use Environment Variables**: For production, use environment variables or secure configuration
5. **Test Thoroughly**: Test with various scenarios before going live
6. **Regular Review**: Review audit logs and Google analytics regularly

## Production Checklist

- [ ] Create `.env` file from `.env.example`
- [ ] Add actual reCAPTCHA keys to `.env` file
- [ ] Verify `.env` is in `.gitignore` (should not be committed)
- [ ] Configure domain in Google reCAPTCHA console
- [ ] Set appropriate RECAPTCHA_SCORE_THRESHOLD (0.5-0.7 recommended)
- [ ] Enable HTTPS (required for production)
- [ ] Test registration and login flows
- [ ] Monitor logs and analytics
- [ ] Set up alerts for high failure rates
- [ ] For production deployment, use environment variables or secure key management (Azure Key Vault, AWS Secrets Manager, etc.)

## Additional Resources

- [Google reCAPTCHA v3 Documentation](https://developers.google.com/recaptcha/docs/v3)
- [reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
- [Score Interpretation Guide](https://developers.google.com/recaptcha/docs/v3#interpreting_the_score)

