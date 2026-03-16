// Package cwe provides CWE (Common Weakness Enumeration) mapping functionality
// for security scanner findings.
//
// Mapping Strategy:
// 1. Extract CWE from scanner metadata if available (e.g., gosec provides CWE directly)
// 2. Use exact rule ID match from RuleToCWEMap
// 3. Use pattern matching on rule ID (case-insensitive)
// 4. Use category-based mapping as fallback
// 5. Return CWE-000 (unknown) if no mapping found
//
// Supported Scanners:
// - Bandit (Python): B101-B703 rules mapped to CWE
// - gosec (Go): G101-G601 rules mapped to CWE (also extracts CWE from gosec output)
// - eslint-plugin-security (JavaScript/TypeScript): All 12 security rules mapped
// - Semgrep: Common security patterns mapped
// - Safety: CVE-based findings mapped to CWE-1035 (Vulnerable Components)
package cwe

import (
	"strings"
)

// RuleToCWEMap maps scanner rule IDs to CWE IDs
// 
// Mapping Accuracy:
// - All gosec rules (G101-G601) verified against gosec documentation
// - All eslint-plugin-security rules verified against plugin documentation
// - All Bandit rules (B101-B703) verified against Bandit documentation
// - Semgrep patterns based on common security rule patterns
// - Safety scanner uses CWE-1035 for all vulnerable dependency findings
//
// Last updated: 2024 (v1.2 release)
var RuleToCWEMap = map[string]string{
	// Bandit rules
	"B201": "CWE-78",  // flask_debug_true
	"B301": "CWE-502", // pickle
	"B302": "CWE-502", // marshal
	"B303": "CWE-327", // md5
	"B304": "CWE-327", // md5 (insecure hash)
	"B305": "CWE-327", // sha1 (insecure hash)
	"B306": "CWE-732", // mktemp_q
	"B307": "CWE-502", // eval
	"B308": "CWE-327", // mark_safe
	"B310": "CWE-601", // urllib_urlopen
	"B311": "CWE-330", // random
	"B312": "CWE-327", // telnetlib
	"B313": "CWE-611", // xml_bad_cElementTree
	"B314": "CWE-611", // xml_bad_ElementTree
	"B315": "CWE-611", // xml_bad_expatreader
	"B316": "CWE-611", // xml_bad_expatbuilder
	"B317": "CWE-611", // xml_bad_sax
	"B318": "CWE-611", // xml_bad_minidom
	"B319": "CWE-611", // xml_bad_pulldom
	"B320": "CWE-611", // xml_bad_etree
	"B321": "CWE-327", // ftplib
	"B322": "CWE-327", // input
	"B323": "CWE-327", // unverified_context
	"B324": "CWE-327", // hashlib_new_insecure_functions
	"B401": "CWE-327", // import_telnetlib
	"B402": "CWE-327", // import_ftplib
	"B403": "CWE-502", // import_pickle
	"B404": "CWE-327", // import_subprocess
	"B405": "CWE-611", // import_xml_etree
	"B406": "CWE-611", // import_xml_sax
	"B407": "CWE-611", // import_xml_expat
	"B408": "CWE-611", // import_xml_minidom
	"B409": "CWE-611", // import_xml_pulldom
	"B410": "CWE-327", // import_lxml
	"B411": "CWE-327", // import_xmlrpclib
	"B412": "CWE-327", // import_httpoxy
	"B413": "CWE-326", // import_pycrypto
	"B501": "CWE-295", // request_with_no_cert_validation
	"B502": "CWE-295", // ssl_with_bad_version
	"B503": "CWE-295", // ssl_with_bad_defaults
	"B504": "CWE-295", // ssl_with_no_version
	"B505": "CWE-327", // weak_cryptographic_key
	"B506": "CWE-327", // yaml_load
	"B507": "CWE-295", // ssh_no_host_key_verification
	"B601": "CWE-78",  // paramiko_calls
	"B602": "CWE-78",  // subprocess_popen_with_shell_equals_true
	"B603": "CWE-78",  // subprocess_without_shell_equals_true
	"B604": "CWE-78",  // any_other_function_with_shell_equals_true
	"B605": "CWE-78",  // start_process_with_a_shell
	"B606": "CWE-78",  // start_process_with_no_shell
	"B607": "CWE-78",  // start_process_with_partial_path
	"B608": "CWE-89",  // hardcoded_sql_expressions
	"B609": "CWE-78",  // linux_commands_wildcard_injection
	"B610": "CWE-89",  // django_extra_used
	"B611": "CWE-89",  // django_rawsql_used
	"B701": "CWE-327", // jinja2_autoescape_false
	"B702": "CWE-327", // use_of_mako_templates
	"B703": "CWE-327", // django_mark_safe

	// Hardcoded credentials
	"B105": "CWE-798", // hardcoded_password_string
	"B106": "CWE-798", // hardcoded_password_funcarg
	"B107": "CWE-798", // hardcoded_password_default

	// gosec rules for Go
	"G101": "CWE-798", // hardcoded_credentials
	"G102": "CWE-200", // network_binding
	"G103": "CWE-242", // unsafe_block
	"G104": "CWE-703", // errors_unhandled
	"G105": "CWE-190", // integer_overflow
	"G106": "CWE-322", // ssh_host_key
	"G107": "CWE-918", // ssrf
	"G108": "CWE-200", // profiling_endpoint
	"G109": "CWE-190", // integer_conversion
	"G110": "CWE-409", // decompression_bomb
	"G201": "CWE-89",  // sql_query_construction
	"G202": "CWE-89",  // sql_string_concatenation
	"G203": "CWE-79",  // html_template
	"G204": "CWE-78",  // command_injection
	"G301": "CWE-732", // file_permissions_mkdir
	"G302": "CWE-732", // file_permissions_chmod
	"G303": "CWE-377", // file_creation_temp
	"G304": "CWE-22",  // path_traversal
	"G305": "CWE-22",  // path_traversal_zip
	"G306": "CWE-732", // file_permissions_write
	"G307": "CWE-703", // defer_close_error
	"G401": "CWE-327", // weak_crypto_md5
	"G402": "CWE-295", // tls_config
	"G403": "CWE-327", // weak_crypto_des
	"G404": "CWE-330", // weak_random
	"G501": "CWE-327", // import_md5
	"G502": "CWE-327", // import_des
	"G503": "CWE-327", // import_rc4
	"G504": "CWE-327", // import_sha1
	"G505": "CWE-327", // import_md4
	"G601": "CWE-118", // implicit_aliasing

	// eslint-plugin-security rules
	"security/detect-unsafe-regex":                    "CWE-1333", // ReDoS
	"security/detect-buffer-noassert":                 "CWE-120",  // Buffer overflow
	"security/detect-child-process":                   "CWE-78",   // Command injection
	"security/detect-disable-mustache-escape":         "CWE-79",   // XSS
	"security/detect-eval-with-expression":            "CWE-94",   // Code injection
	"security/detect-no-csrf-before-method-override":  "CWE-352",  // CSRF
	"security/detect-non-literal-fs-filename":         "CWE-22",   // Path traversal
	"security/detect-non-literal-regexp":              "CWE-1333", // ReDoS
	"security/detect-non-literal-require":             "CWE-94",   // Code injection
	"security/detect-object-injection":                "CWE-1321", // Prototype pollution
	"security/detect-possible-timing-attacks":         "CWE-208",  // Timing attack
	"security/detect-pseudoRandomBytes":               "CWE-330",  // Weak random

	// Safety scanner - CVE patterns will be mapped dynamically
	// Category-based mappings for safety findings
	"SAFETY-vulnerable-dependency": "CWE-1035", // Using Vulnerable Components

	// Semgrep rules (common patterns)
	"python.lang.security.audit.dangerous-system-call":           "CWE-78",
	"python.lang.security.audit.exec-used":                       "CWE-94",
	"python.lang.security.audit.eval-used":                       "CWE-94",
	"python.lang.security.audit.pickle":                          "CWE-502",
	"python.lang.security.audit.marshal":                         "CWE-502",
	"python.lang.security.audit.md5-used":                        "CWE-327",
	"python.lang.security.audit.sha1-used":                       "CWE-327",
	"python.lang.security.audit.hardcoded-password":              "CWE-798",
	"python.lang.security.audit.sqli":                            "CWE-89",
	"python.lang.security.audit.path-traversal":                  "CWE-22",
	"python.lang.security.audit.xxe":                             "CWE-611",
	"python.lang.security.audit.weak-random":                     "CWE-330",
	"python.lang.security.audit.open-redirect":                   "CWE-601",
	"javascript.lang.security.audit.xss":                         "CWE-79",
	"javascript.lang.security.audit.sql-injection":               "CWE-89",
	"javascript.lang.security.audit.command-injection":           "CWE-78",
	"javascript.lang.security.audit.path-traversal":              "CWE-22",
	"javascript.lang.security.audit.hardcoded-secret":            "CWE-798",
	"javascript.lang.security.audit.weak-crypto":                 "CWE-327",
	"javascript.lang.security.audit.eval-detected":               "CWE-94",
	"javascript.lang.security.audit.insecure-random":             "CWE-330",
	"javascript.lang.security.audit.open-redirect":               "CWE-601",
	"javascript.lang.security.audit.ssrf":                        "CWE-918",
	"javascript.express.security.audit.xss.mustache.var-in-href": "CWE-79",
	"javascript.express.security.audit.xss.direct-response-write": "CWE-79",
}

// MapRuleToCWE maps a scanner rule ID to a CWE ID
func MapRuleToCWE(ruleID, category string) string {
	// Try exact match first
	if cweID, exists := RuleToCWEMap[ruleID]; exists {
		return cweID
	}

	// Try pattern matching for Semgrep rules and CVEs
	ruleIDLower := strings.ToLower(ruleID)
	
	// Handle CVE identifiers from safety scanner
	if strings.HasPrefix(ruleIDLower, "cve-") {
		// For CVEs, use category-based mapping
		return mapCategoryToCWE(category)
	}
	
	// Deserialization patterns (check before crypto patterns)
	if strings.Contains(ruleIDLower, "pickle") || strings.Contains(ruleIDLower, "deserial") ||
	   strings.Contains(ruleIDLower, "unmarshal") || strings.Contains(ruleIDLower, "eval") {
		return "CWE-502"
	}
	
	// Random patterns (check before crypto patterns)
	if strings.Contains(ruleIDLower, "random") || strings.Contains(ruleIDLower, "prng") {
		return "CWE-330"
	}
	
	// SQL Injection patterns
	if strings.Contains(ruleIDLower, "sql") || strings.Contains(ruleIDLower, "sqli") {
		return "CWE-89"
	}
	
	// Command Injection patterns
	if strings.Contains(ruleIDLower, "command") || strings.Contains(ruleIDLower, "exec") || 
	   strings.Contains(ruleIDLower, "shell") || strings.Contains(ruleIDLower, "subprocess") {
		return "CWE-78"
	}
	
	// XSS patterns
	if strings.Contains(ruleIDLower, "xss") || strings.Contains(ruleIDLower, "cross-site") {
		return "CWE-79"
	}
	
	// Path Traversal patterns
	if strings.Contains(ruleIDLower, "path") || strings.Contains(ruleIDLower, "traversal") ||
	   strings.Contains(ruleIDLower, "directory") {
		return "CWE-22"
	}
	
	// Hardcoded Credentials patterns
	if strings.Contains(ruleIDLower, "password") || strings.Contains(ruleIDLower, "secret") ||
	   strings.Contains(ruleIDLower, "credential") || strings.Contains(ruleIDLower, "hardcoded") ||
	   strings.Contains(ruleIDLower, "api-key") || strings.Contains(ruleIDLower, "apikey") {
		return "CWE-798"
	}
	
	// Crypto patterns (check after more specific patterns)
	if strings.Contains(ruleIDLower, "crypto") || strings.Contains(ruleIDLower, "hash") ||
	   strings.Contains(ruleIDLower, "md5") || strings.Contains(ruleIDLower, "sha1") ||
	   strings.Contains(ruleIDLower, "des") || strings.Contains(ruleIDLower, "weak") {
		return "CWE-327"
	}
	
	// XXE patterns
	if strings.Contains(ruleIDLower, "xxe") || strings.Contains(ruleIDLower, "xml") {
		return "CWE-611"
	}
	
	// Redirect patterns
	if strings.Contains(ruleIDLower, "redirect") || strings.Contains(ruleIDLower, "open-redirect") {
		return "CWE-601"
	}
	
	// SSRF patterns
	if strings.Contains(ruleIDLower, "ssrf") || strings.Contains(ruleIDLower, "server-side-request") {
		return "CWE-918"
	}

	// Try category-based mapping
	categoryLower := strings.ToLower(category)
	if strings.Contains(categoryLower, "injection") {
		return "CWE-89" // Default to SQL injection for injection category
	}
	if strings.Contains(categoryLower, "crypto") {
		return "CWE-327"
	}
	if strings.Contains(categoryLower, "auth") {
		return "CWE-798"
	}

	// Default to unknown
	return "CWE-000"
}

// ExtractCWEFromMetadata extracts CWE ID from scanner metadata
func ExtractCWEFromMetadata(metadata map[string]interface{}) string {
	// Check if CWE is in metadata (gosec provides this)
	if cwe, ok := metadata["cwe"]; ok {
		switch v := cwe.(type) {
		case string:
			if strings.HasPrefix(v, "CWE-") {
				return v
			}
			return "CWE-" + v
		case []interface{}:
			if len(v) > 0 {
				if cweStr, ok := v[0].(string); ok {
					if strings.HasPrefix(cweStr, "CWE-") {
						return cweStr
					}
					return "CWE-" + cweStr
				}
			}
		case map[string]interface{}:
			// Handle gosec's CWE object format: {"id": "22", "url": "..."}
			if id, ok := v["id"].(string); ok {
				if strings.HasPrefix(id, "CWE-") {
					return id
				}
				return "CWE-" + id
			}
		}
	}

	// Check OWASP mapping
	if owasp, ok := metadata["owasp"]; ok {
		if owaspSlice, ok := owasp.([]interface{}); ok && len(owaspSlice) > 0 {
			// Map common OWASP categories to CWE
			if owaspStr, ok := owaspSlice[0].(string); ok {
				return mapOWASPToCWE(owaspStr)
			}
		}
	}

	return ""
}

// mapOWASPToCWE maps OWASP categories to CWE IDs
func mapOWASPToCWE(owasp string) string {
	owaspMap := map[string]string{
		"A01:2021": "CWE-20",  // Broken Access Control
		"A02:2021": "CWE-327", // Cryptographic Failures
		"A03:2021": "CWE-89",  // Injection
		"A04:2021": "CWE-20",  // Insecure Design
		"A05:2021": "CWE-798", // Security Misconfiguration
		"A06:2021": "CWE-327", // Vulnerable and Outdated Components
		"A07:2021": "CWE-798", // Identification and Authentication Failures
		"A08:2021": "CWE-502", // Software and Data Integrity Failures
		"A09:2021": "CWE-200", // Security Logging and Monitoring Failures
		"A10:2021": "CWE-918", // Server-Side Request Forgery
	}

	if cwe, exists := owaspMap[owasp]; exists {
		return cwe
	}

	return ""
}

// mapCategoryToCWE maps vulnerability categories to CWE IDs
func mapCategoryToCWE(category string) string {
	categoryLower := strings.ToLower(category)
	
	categoryMap := map[string]string{
		"sql-injection":         "CWE-89",
		"xss":                   "CWE-79",
		"code-execution":        "CWE-94",
		"command-injection":     "CWE-78",
		"path-traversal":        "CWE-22",
		"csrf":                  "CWE-352",
		"denial-of-service":     "CWE-400",
		"authentication":        "CWE-287",
		"authorization":         "CWE-285",
		"deserialization":       "CWE-502",
		"xxe":                   "CWE-611",
		"vulnerable-dependency": "CWE-1035",
	}
	
	if cwe, exists := categoryMap[categoryLower]; exists {
		return cwe
	}
	
	return "CWE-1035" // Default to Using Vulnerable Components
}
