package cwe

// CWEInfo represents information about a CWE
type CWEInfo struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Category    string
}

// CWEDatabase is a mapping of CWE IDs to their information
var CWEDatabase = map[string]CWEInfo{
	// Injection Flaws
	"CWE-89": {
		ID:          "CWE-89",
		Name:        "SQL Injection",
		Description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
		Severity:    "critical",
		Category:    "injection",
	},
	"CWE-78": {
		ID:          "CWE-78",
		Name:        "OS Command Injection",
		Description: "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
		Severity:    "critical",
		Category:    "injection",
	},
	"CWE-79": {
		ID:          "CWE-79",
		Name:        "Cross-site Scripting (XSS)",
		Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
		Severity:    "high",
		Category:    "injection",
	},
	"CWE-94": {
		ID:          "CWE-94",
		Name:        "Code Injection",
		Description: "The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.",
		Severity:    "critical",
		Category:    "injection",
	},

	// Cryptographic Issues
	"CWE-327": {
		ID:          "CWE-327",
		Name:        "Use of a Broken or Risky Cryptographic Algorithm",
		Description: "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
		Severity:    "high",
		Category:    "cryptography",
	},
	"CWE-326": {
		ID:          "CWE-326",
		Name:        "Inadequate Encryption Strength",
		Description: "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.",
		Severity:    "high",
		Category:    "cryptography",
	},
	"CWE-328": {
		ID:          "CWE-328",
		Name:        "Reversible One-Way Hash",
		Description: "The product uses a hashing algorithm that produces a hash value that can be used to determine the original input, or to find an input that can produce the same hash, more efficiently than brute force techniques.",
		Severity:    "high",
		Category:    "cryptography",
	},

	// Authentication & Access Control
	"CWE-798": {
		ID:          "CWE-798",
		Name:        "Use of Hard-coded Credentials",
		Description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.",
		Severity:    "critical",
		Category:    "authentication",
	},
	"CWE-259": {
		ID:          "CWE-259",
		Name:        "Use of Hard-coded Password",
		Description: "The software contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.",
		Severity:    "critical",
		Category:    "authentication",
	},
	"CWE-321": {
		ID:          "CWE-321",
		Name:        "Use of Hard-coded Cryptographic Key",
		Description: "The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.",
		Severity:    "critical",
		Category:    "authentication",
	},
	"CWE-522": {
		ID:          "CWE-522",
		Name:        "Insufficiently Protected Credentials",
		Description: "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.",
		Severity:    "high",
		Category:    "authentication",
	},

	// Path Traversal & File Handling
	"CWE-22": {
		ID:          "CWE-22",
		Name:        "Path Traversal",
		Description: "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
		Severity:    "high",
		Category:    "path-traversal",
	},
	"CWE-73": {
		ID:          "CWE-73",
		Name:        "External Control of File Name or Path",
		Description: "The software allows user input to control or influence paths or file names that are used in filesystem operations.",
		Severity:    "high",
		Category:    "path-traversal",
	},

	// Deserialization
	"CWE-502": {
		ID:          "CWE-502",
		Name:        "Deserialization of Untrusted Data",
		Description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
		Severity:    "critical",
		Category:    "deserialization",
	},

	// XML Issues
	"CWE-611": {
		ID:          "CWE-611",
		Name:        "Improper Restriction of XML External Entity Reference",
		Description: "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
		Severity:    "high",
		Category:    "xml",
	},

	// Random Number Generation
	"CWE-330": {
		ID:          "CWE-330",
		Name:        "Use of Insufficiently Random Values",
		Description: "The software uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.",
		Severity:    "medium",
		Category:    "randomness",
	},
	"CWE-338": {
		ID:          "CWE-338",
		Name:        "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
		Description: "The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG's algorithm is not cryptographically strong.",
		Severity:    "medium",
		Category:    "randomness",
	},

	// Redirect & SSRF
	"CWE-601": {
		ID:          "CWE-601",
		Name:        "URL Redirection to Untrusted Site ('Open Redirect')",
		Description: "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.",
		Severity:    "medium",
		Category:    "redirect",
	},
	"CWE-918": {
		ID:          "CWE-918",
		Name:        "Server-Side Request Forgery (SSRF)",
		Description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
		Severity:    "high",
		Category:    "ssrf",
	},

	// File Permissions
	"CWE-732": {
		ID:          "CWE-732",
		Name:        "Incorrect Permission Assignment for Critical Resource",
		Description: "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.",
		Severity:    "medium",
		Category:    "permissions",
	},

	// Cookie Security
	"CWE-614": {
		ID:          "CWE-614",
		Name:        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
		Description: "The Secure attribute for sensitive cookies in HTTPS sessions is not set, which could cause the user agent to send those cookies in plaintext over an HTTP session.",
		Severity:    "medium",
		Category:    "cookie",
	},

	// Information Exposure
	"CWE-200": {
		ID:          "CWE-200",
		Name:        "Exposure of Sensitive Information to an Unauthorized Actor",
		Description: "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
		Severity:    "medium",
		Category:    "information-disclosure",
	},
	"CWE-209": {
		ID:          "CWE-209",
		Name:        "Generation of Error Message Containing Sensitive Information",
		Description: "The software generates an error message that includes sensitive information about its environment, users, or associated data.",
		Severity:    "low",
		Category:    "information-disclosure",
	},

	// Input Validation
	"CWE-20": {
		ID:          "CWE-20",
		Name:        "Improper Input Validation",
		Description: "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
		Severity:    "medium",
		Category:    "input-validation",
	},

	// Race Conditions
	"CWE-362": {
		ID:          "CWE-362",
		Name:        "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
		Description: "The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.",
		Severity:    "medium",
		Category:    "concurrency",
	},

	// Buffer Errors
	"CWE-119": {
		ID:          "CWE-119",
		Name:        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
		Description: "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
		Severity:    "critical",
		Category:    "buffer-overflow",
	},
	"CWE-120": {
		ID:          "CWE-120",
		Name:        "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
		Description: "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer, leading to a buffer overflow.",
		Severity:    "critical",
		Category:    "buffer-overflow",
	},

	// Default/Placeholder
	"CWE-000": {
		ID:          "CWE-000",
		Name:        "Unknown Vulnerability",
		Description: "The vulnerability type could not be determined or mapped to a specific CWE.",
		Severity:    "medium",
		Category:    "unknown",
	},
}

// GetCWEInfo retrieves CWE information by ID
func GetCWEInfo(cweID string) (CWEInfo, bool) {
	info, exists := CWEDatabase[cweID]
	return info, exists
}

// GetCWEDescription returns the description for a CWE ID
func GetCWEDescription(cweID string) string {
	if info, exists := CWEDatabase[cweID]; exists {
		return info.Description
	}
	return "No description available"
}

// GetCWESeverity returns the severity for a CWE ID
func GetCWESeverity(cweID string) string {
	if info, exists := CWEDatabase[cweID]; exists {
		return info.Severity
	}
	return "medium"
}

// GetCWEName returns the name for a CWE ID
func GetCWEName(cweID string) string {
	if info, exists := CWEDatabase[cweID]; exists {
		return info.Name
	}
	return "Unknown Vulnerability"
}
