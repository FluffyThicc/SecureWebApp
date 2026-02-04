# Security Features Implementation

## ✅ 1. Strong Password Requirements

### Server-Side Validation
- **Location:** `ViewModels/PasswordStrengthAttribute.cs`
- **Requirements:**
  - Minimum 12 characters ✅
  - At least one lowercase letter (a-z) ✅
  - At least one uppercase letter (A-Z) ✅
  - At least one number (0-9) ✅
  - At least one special character (!@#$%^&*, etc.) ✅

### Client-Side Validation
- **Location:** `Views/Account/Register.cshtml` (JavaScript)
- **Features:**
  - Real-time password strength indicator (Weak/Medium/Strong)
  - Visual feedback with color-coded progress bar
  - Checklist showing which requirements are met
  - Password match indicator for Confirm Password field

### Identity Configuration
- **Location:** `Program.cs` (lines 25-29)
- **Settings:**
  ```csharp
  options.Password.RequiredLength = 12;
  options.Password.RequireDigit = true;
  options.Password.RequireLowercase = true;
  options.Password.RequireUppercase = true;
  options.Password.RequireNonAlphanumeric = true;
  ```

---

## ✅ 2. Password Protection

### Password Hashing
- **Method:** ASP.NET Core Identity uses PBKDF2 algorithm
- **Storage:** Passwords are NEVER stored in plain text
- **Location:** Automatically handled by `UserManager.CreateAsync()`
- **Database:** Only `PasswordHash` field is stored (hashed, not plain password)

### Password Security Features
- Account lockout after 5 failed attempts (5-minute lockout)
- Password complexity enforced at multiple levels
- No password stored in ApplicationUser model (only hash)

---

## ✅ 3. Data Encryption & Decryption

### NRIC Encryption
- **Service:** `Services/EncryptionService.cs`
- **Algorithm:** AES-256 (Advanced Encryption Standard)
- **Mode:** CBC (Cipher Block Chaining)
- **Key Management:** Stored in `appsettings.json` under `Encryption:Key`

### Encryption Process
- **Location:** `Controllers/AccountController.cs` (line 99)
- **Before Save:** NRIC is encrypted using `EncryptionService.Encrypt()`
- **Database:** Encrypted NRIC stored in `EncryptedNRIC` field

### Decryption Process
- **Location:** `Controllers/HomeController.cs` (line 40)
- **Before Display:** NRIC is decrypted using `EncryptionService.Decrypt()`
- **Homepage:** Decrypted NRIC displayed to authenticated user

### How It Works:
```csharp
// During Registration (Encryption)
var encryptedNRIC = _encryptionService.Encrypt(model.NRIC);
user.EncryptedNRIC = encryptedNRIC; // Saved to database

// During Display (Decryption)
NRIC = _encryptionService.Decrypt(user.EncryptedNRIC); // Displayed on homepage
```

---

## 🔒 Security Implementation Checklist

### Strong Password ✅
- [x] Minimum 12 characters
- [x] Uppercase letters required
- [x] Lowercase letters required
- [x] Numbers required
- [x] Special characters required
- [x] Client-side validation with visual feedback
- [x] Server-side validation (multiple layers)
- [x] Password strength indicator (Weak/Medium/Strong)

### Password Protection ✅
- [x] Passwords hashed using PBKDF2
- [x] No plain text passwords stored
- [x] Account lockout mechanism
- [x] Password complexity validation

### Data Encryption ✅
- [x] NRIC encrypted before database storage
- [x] AES-256 encryption algorithm
- [x] Secure key management (appsettings.json)
- [x] NRIC decrypted for display on homepage
- [x] Encryption key separate from codebase

---

## 📍 File Locations

### Password Validation
- `ViewModels/PasswordStrengthAttribute.cs` - Server-side validation attribute
- `Controllers/AccountController.cs` - Additional server-side validation (line 43, 218-243)
- `Views/Account/Register.cshtml` - Client-side validation with JavaScript

### Encryption/Decryption
- `Services/EncryptionService.cs` - Encryption service
- `Controllers/AccountController.cs` - Encryption during registration (line 99)
- `Controllers/HomeController.cs` - Decryption for display (line 40)

### Configuration
- `Program.cs` - Password requirements configuration (lines 25-29)
- `appsettings.json` - Encryption key storage

---

## 🎯 How to Test

### Password Strength
1. Navigate to Registration page
2. Start typing password - see real-time strength indicator
3. Watch requirements checklist update as you type
4. Try submitting weak password - see validation errors
5. Enter strong password (12+ chars, all requirements) - see "Strong" indicator

### Encryption/Decryption
1. Register a new user with NRIC (e.g., S1234567A)
2. Check database - NRIC should be encrypted (base64 string)
3. Login and view homepage - NRIC should display correctly (decrypted)

### Server-Side Validation
1. Try bypassing client-side validation
2. Submit form with weak password via API/direct POST
3. Server should reject and return validation errors

