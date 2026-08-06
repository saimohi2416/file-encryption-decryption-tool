# Privacy Policy for SecureVault AI

**Effective Date:** August 6, 2026

**Application Name:** SecureVault AI  
**Package Name:** `com.securevault.ai.app`  
**Developer/Organization:** SecureVault Team  
**Website:** https://securevault-ai-two.vercel.app/

---

## 1. Introduction
Welcome to **SecureVault AI**. We prioritize user privacy and data security above all else. This Privacy Policy explains how our application handles your data, encryption keys, and personal information when using our Android App and Web service.

## 2. Core Privacy Philosophy: Zero-Knowledge Architecture
SecureVault AI is built on a strict **zero-knowledge, client-side security model**:
- **Client-Side Encryption**: All file encryptions, decryptions, key generations, and cryptographic operations are executed locally within your device's browser / Trusted Web Activity runtime using standard WebCrypto APIs (AES-GCM / PBKDF2 / Argon2).
- **No Master Key Storage**: Your secret passwords, encryption keys, and unencrypted files are **never** transmitted to or stored on our servers.
- **Data Control**: You retain full ownership and exclusive control over your encrypted assets and keys.

## 3. Information We Collect
Because SecureVault AI operates locally on your device:
- **Personal Data**: We do **NOT** collect, request, or store personal identity information (such as your name, phone number, physical address, or social security number).
- **File Content**: Your uploaded or encrypted files remain exclusively on your device unless explicitly shared by you via generated cryptographic links.
- **Local Storage**: Preferences, theme settings, and transient session keys are stored locally in your app’s browser storage (`localStorage` / `IndexedDB`) and are never sent to external tracking services.
- **AI Security Assistant**: Prompts sent to the AI security chatbot helper are processed securely for answering security and cryptographic queries without storing or associating your private files.

## 4. Third-Party Services & Hosting
- **Hosting Infrastructure**: SecureVault AI is hosted via [Vercel](https://vercel.com). Standard anonymized web access logs (IP addresses, user-agent HTTP headers) may be logged by Vercel for infrastructure health, DDoS protection, and routing.
- **No Analytics / Ad Trackers**: SecureVault AI does **not** include third-party advertising SDKs, cross-app tracking networks, or intrusive analytics cookies.

## 5. Security Measures
We employ industry-standard security protocols:
- **HTTPS Enforcement**: All web and app communication requires TLS 1.3 encryption.
- **Digital Asset Links**: Android TWA integration is verified via Google Digital Asset Links (`assetlinks.json`) to guarantee authentic domain connection.
- **Secure Runtime**: Sandboxed Android Trusted Web Activity container ensuring zero unauthorized file access.

## 6. Permissions Required
- **Internet Access (`android.permission.INTERNET`)**: Required to fetch web assets and communicate with the Vercel hosted endpoint.
- **Storage Access**: Required to select files for local encryption and download decrypted files to your device.

## 7. Children's Privacy
SecureVault AI does not target or knowingly collect data from children under 13 years of age.

## 8. Updates to This Privacy Policy
We may update this Privacy Policy periodically to reflect app updates or regulatory changes. Updated policies will be posted directly within the app and at our official web URL.

## 9. Contact Us
If you have questions regarding this Privacy Policy or security practices, please contact us via our official repository or website at:  
[https://securevault-ai-two.vercel.app/](https://securevault-ai-two.vercel.app/)
