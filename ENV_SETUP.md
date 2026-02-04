# Environment Variables Setup Guide

## Overview
Sensitive configuration values (reCAPTCHA keys, encryption keys) are now stored in a `.env` file instead of `appsettings.json` for better security.

## Quick Setup

### Step 1: Create `.env` file
Create a `.env` file in the project root directory with the following content:

```env
# Google reCAPTCHA v3 Configuration
# Get your keys from: https://www.google.com/recaptcha/admin

# Site Key (public key - used in frontend)
RECAPTCHA_SITE_KEY=your_actual_site_key_here

# Secret Key (private key - used in backend)
RECAPTCHA_SECRET_KEY=your_actual_secret_key_here

# Score Threshold (0.0 to 1.0, default: 0.5)
# Higher values = stricter (more likely to block bots)
# Typical values: 0.5 to 0.7
RECAPTCHA_SCORE_THRESHOLD=0.5

# Encryption Key (for NRIC encryption)
# Generate a secure 64-character key for production
ENCRYPTION_KEY=AceJobAgency2024SecureEncryptionKey123456789012345678901234567890
```

### Step 2: Fill in your actual keys
1. Replace `your_actual_site_key_here` with your reCAPTCHA Site Key
2. Replace `your_actual_secret_key_here` with your reCAPTCHA Secret Key
3. Adjust `RECAPTCHA_SCORE_THRESHOLD` if needed (default: 0.5)
4. Generate a secure encryption key for production (replace the default `ENCRYPTION_KEY`)

### Step 3: Verify .env is ignored
The `.env` file is already added to `.gitignore`, so it won't be committed to version control. ✅

## Security Notes

⚠️ **IMPORTANT**:
- Never commit the `.env` file to version control
- Never share your Secret Key publicly
- For production, use secure key management services (Azure Key Vault, AWS Secrets Manager, etc.)
- Generate a strong, random encryption key for production use

## How It Works

1. The application uses the `DotNetEnv` package to load environment variables from the `.env` file
2. Environment variables take precedence over `appsettings.json` values
3. If `.env` file doesn't exist, the application falls back to `appsettings.json` (which has no actual keys)

## Getting reCAPTCHA Keys

1. Visit [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
2. Click "Create" to create a new site
3. Select **reCAPTCHA v3**
4. Add your domain (e.g., `localhost` for development)
5. Accept the terms and submit
6. Copy the **Site Key** and **Secret Key**

## Troubleshooting

### Application not loading .env file
- Ensure `.env` file is in the project root directory (same level as `Program.cs`)
- Verify `DotNetEnv` package is installed: `dotnet restore`
- Check file name is exactly `.env` (not `.env.txt` or `.env.example`)

### Keys not being read
- Verify environment variable names are correct (all uppercase, underscores)
- Check that values don't have extra spaces or quotes
- Restart the application after modifying `.env`

### Still seeing "reCAPTCHA verification failed"
- Verify keys are correct in `.env` file
- Check domain matches in Google reCAPTCHA console
- Ensure `.env` file is being loaded (check application startup logs)





