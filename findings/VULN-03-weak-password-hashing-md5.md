# [VULN-03] Weak Password Storage Using Unsalted MD5 Hashing

- **Severity:** Low
- **CWE:** [CWE-916 – Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html), [CWE-759 – Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
- **Affected endpoint:** `/vulnerabilities/brute/`
- **Affected security levels:** Low, Medium, High and Impossible
- **Remediation status:** Unaddressed across all security levels
- **Affected components:** `vulnerabilities/brute/source/{low,medium,high,impossible}.php`

## Summary

Static source code analysis of the DVWA authentication handlers revealed that user passwords are hashed using PHP's legacy, unsalted MD5 (`md5()`) function across all four security configurations, including the `Impossible` level.

MD5 is a general-purpose cryptographic hash function designed for computational efficiency rather than password storage. Unlike dedicated password-hashing algorithms, it does not provide an adaptive work factor to make password guessing computationally expensive. Furthermore, the absence of unique per-user salts means identical passwords produce identical hashes.

If an attacker obtains the application's password database through a separate database disclosure or compromise, the stored hashes can be subjected to offline dictionary and brute-force attacks. Weak or commonly reused passwords may therefore be recovered, potentially exposing user accounts and credentials reused across other services.

Although the `Impossible` security configuration introduces parameterised SQL queries, CSRF protection and account lockout mechanisms, it retains the same MD5 password-hashing implementation found in the other configurations.

## Business Impact

If deployed in a production environment, storing user passwords as unsalted MD5 digests increases the risk of credential compromise following a database breach, SQL injection vulnerability or unauthorised backup exposure.

Because MD5 is computationally inexpensive, attackers who obtain password hashes can perform high-speed offline dictionary and brute-force attacks using readily available tools and hardware. Common or weak passwords may be recovered quickly, potentially allowing attackers to authenticate as legitimate users or administrators.

Additionally, users who reuse passwords across multiple services may expose their accounts on external platforms if recovered credentials are reused elsewhere.

Although exploitation of this weakness requires prior access to the stored password hashes, the absence of salting and adaptive password hashing removes an important layer of protection for authentication credentials.

## Password Hashing Comparison Across Security Levels

The server-side password verification logic was reviewed across all four DVWA security implementations.

| Security control | Low | Medium | High | Impossible |
|---|---|---|---|---|
| Hashing algorithm | MD5 (`md5()`) | MD5 (`md5()`) | MD5 (`md5()`) | MD5 (`md5()`) |
| Per-user cryptographic salt | None | None | None | None |
| Adaptive work factor | None | None | None | None |
| Susceptible to high-speed offline password cracking | Yes | Yes | Yes | Yes |

Although the `Impossible` security level introduces parameterised queries, anti-CSRF validation and account lockout mechanisms, it retains the same `md5($pass)` hashing logic used in the Low, Medium and High implementations.

Consequently, the additional authentication and database security controls do not address the underlying weakness in password storage.

## Proof of Concept

**Testing methodology:** Static source code review of all four authentication implementations, supplemented by an independent MD5 hash lookup demonstration.

1. Inspect the authentication source files under `vulnerabilities/brute/source/`, including `low.php`, `medium.php`, `high.php` and `impossible.php`.

2. Observe that user-supplied passwords are passed through PHP's built-in `md5()` function before being compared against the stored database value.

   The following example illustrates the password-processing logic:

   ```php
   // Password processing
   $pass = $_POST['password'];
   $pass = stripslashes($pass);
   $pass = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $pass);
   $pass = md5($pass);
   ```

3. Verify the deterministic output of an unsalted MD5 digest using a common test password:

   ```text
   MD5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
   ```

4. Submit the resulting digest to a publicly available hash lookup service or compare it against an offline password dictionary. The digest can be identified as the original plaintext password, demonstrating the weakness of using a fast, unsalted hashing algorithm for password storage.

**Result:** Static source code analysis confirmed that all four DVWA security levels rely on unsalted MD5 hashing for password verification. An independent hash lookup demonstrated that common MD5 password digests can be identified using publicly available resources.

No extraction or recovery of passwords from the target database was performed.

## Root Cause Analysis

The vulnerability stems from using a general-purpose, fast message-digest algorithm (`md5()`) instead of a dedicated password-hashing function designed to resist offline password-cracking attempts.

In `vulnerabilities/brute/source/impossible.php`, as well as the Low, Medium and High implementations, the application hashes the submitted password using `md5($pass)` before comparing it against the stored password hash.

For example, the Impossible implementation uses parameterised queries for authentication:

```php
$data = $db->prepare(
    'SELECT * FROM users
     WHERE user = (:user)
     AND password = (:password)
     LIMIT 1;'
);

$data->bindParam(':user', $user, PDO::PARAM_STR);
$data->bindParam(':password', $pass, PDO::PARAM_STR);
$data->execute();
```

Although parameterised queries protect the SQL statement from injection through user-supplied values, they do not address the security of the password-hashing algorithm itself.

MD5 is computationally inexpensive, allowing attackers to test large numbers of password candidates during offline cracking attempts. Additionally, because no unique salt is applied, identical passwords produce identical hashes, making password reuse easier to identify and enabling attackers to use precomputed hash databases.

The underlying issue is therefore independent of the SQL injection protections implemented at the Impossible security level.

## Remediation

Replace MD5 password hashing with a dedicated password-hashing algorithm such as Argon2id or bcrypt. PHP provides the native `password_hash()` and `password_verify()` functions, which support secure password hashing and verification. These algorithms automatically generate and manage salts, while their configurable computational cost makes offline password cracking significantly more expensive.

For new or updated passwords, the application should generate hashes using an appropriate algorithm and configuration:

```php
// Hashing a new password
$hashedPassword = password_hash(
    $plainPassword,
    PASSWORD_ARGON2ID
);

// Verifying a submitted password
if (password_verify($submittedPassword, $storedHash)) {

    if (password_needs_rehash($storedHash, PASSWORD_ARGON2ID)) {
        // Generate a new hash and update the database
    }
}
```

For existing accounts, legacy MD5 hashes cannot be directly converted into secure password hashes without access to the original plaintext passwords. Organisations migrating from MD5 should transparently rehash passwords using the new algorithm following successful authentication. Accounts that remain inactive beyond a defined migration period should be required to reset their passwords.

The application should also ensure that the database schema accommodates the longer password hashes generated by modern password-hashing algorithms.

## References

- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHP Manual – `password_hash()`](https://www.php.net/manual/en/function.password-hash.php)
- [PHP Manual – `password_verify()`](https://www.php.net/manual/en/function.password-verify.php)
