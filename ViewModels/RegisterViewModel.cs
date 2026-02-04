using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models;

public class RegisterViewModel
{
    [Required(ErrorMessage = "First Name is required")]
    [Display(Name = "First Name")]
    [StringLength(50, ErrorMessage = "First Name cannot exceed 50 characters")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Last Name is required")]
    [Display(Name = "Last Name")]
    [StringLength(50, ErrorMessage = "Last Name cannot exceed 50 characters")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "Gender is required")]
    [Display(Name = "Gender")]
    public string Gender { get; set; } = string.Empty;

    [Required(ErrorMessage = "NRIC is required")]
    [Display(Name = "NRIC")]
    [RegularExpression(@"^[STFG]\d{7}[A-Z]$", ErrorMessage = "Invalid NRIC format. Format: S1234567A")]
    public string NRIC { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email address is required")]
    [EmailAddress(ErrorMessage = "Invalid email address format")]
    [Display(Name = "Email Address")]
    [StringLength(256, ErrorMessage = "Email address cannot exceed 256 characters")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    [PasswordStrength(ErrorMessage = "Password must be at least 12 characters with uppercase, lowercase, number, and special character.")]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Confirm Password is required")]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Date of Birth is required")]
    [Display(Name = "Date of Birth")]
    [DataType(DataType.Date)]
    public DateTime DateOfBirth { get; set; }

    [Required(ErrorMessage = "Resume is required")]
    [Display(Name = "Resume (.docx or .pdf)")]
    [AllowedExtensions(new string[] { ".pdf", ".docx" })]
    public IFormFile Resume { get; set; } = null!;

    [Display(Name = "Who Am I")]
    [StringLength(1000, ErrorMessage = "Who Am I cannot exceed 1000 characters")]
    public string? WhoAmI { get; set; }
}


// Erorr validation for file extensions attribute of .docx and .pdf file 
public class AllowedExtensionsAttribute : ValidationAttribute
{
    private readonly string[] _extensions;

    // The constructor (runs when you create this attribute). 
    //It takes an array of allowed extensions as input and saves them to _extensions. 
    //This is why you can write [AllowedExtensions(new string[] { ".pdf", ".docx" })] 
    //in the first code block.
    public AllowedExtensionsAttribute(string[] extensions)
    {
        _extensions = extensions;
    }

    //This is the main validation method that automatically runs when the form is submitted.
    //It receives the uploaded file as value.
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        if (value is IFormFile file)
        {
            //Extracts the file extension from the filename (e.g., "resume.PDF" becomes ".pdf").
            //ToLowerInvariant() converts it to lowercase so ".PDF" and ".pdf" are treated the same.
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

            //Is the extension empty or null? (no extension found)
            //OR is the extension NOT in our allowed list?
            if (string.IsNullOrEmpty(extension) || !_extensions.Contains(extension))
            {
                return new ValidationResult(GetErrorMessage()); // calls public string function below
            }
        }
        return ValidationResult.Success;
    }


    // Returns error message join the extensions that are allowed and set in the first block of code above
    public string GetErrorMessage()
    {
        return $"Only {string.Join(", ", _extensions)} files are allowed.";
    }
}

