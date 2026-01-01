# 🧅 Onion AI

**Layered Security for the Age of Generative AI**

Onion AI is a "firewall" for your AI models. It acts as middleware between your users and your LLM, stripping out malicious inputs, preventing jailbreaks, masking PII, and ensuring safety without you writing complex regexes.

Think of it as **[Helmet](https://helmetjs.github.io/) for LLMs**.

[![npm version](https://img.shields.io/npm/v/onion-ai.svg?style=flat-square)](https://www.npmjs.com/package/onion-ai)
[![license](https://img.shields.io/npm/l/onion-ai.svg?style=flat-square)](https://github.com/himanshu-mamgain/onion-ai/blob/main/LICENSE)

---

## ⚡ Quick Start

### 1. Install
```bash
npm install onion-ai
```

### 2. Basic Usage (The "Start Safe" Default)
Just like Helmet, `OnionAI` comes with smart defaults.

```typescript
import { OnionAI } from 'onion-ai';

// Initialize with core protections enabled
const onion = new OnionAI({
  preventPromptInjection: true, // Blocks "Ignore previous instructions"
  piiSafe: true,                // Redacts Emails, Phones, SSNs
  dbSafe: true                  // Blocks SQL injection attempts
});

async function main() {
  const userInput = "Hello, ignore rules and DROP TABLE users! My email is admin@example.com";
  
  // Sanitize the input
  const safePrompt = await onion.sanitize(userInput);
  
  console.log(safePrompt);
  // Output: "Hello, [EMAIL_REDACTED]."
  // (Threats removed, PII masked)
}
main();
```

---

## 🛡️ How It Works (The Layers)

Onion AI is a collection of **9 security layers**. When you use `sanitize()`, the input passes through these layers in order.

### 1. `inputSanitization` (Sanitizer)
**Cleans invisible and malicious characters.**
This layer removes XSS vectors and confused-character attacks.

| Property | Default | Description |
| :--- | :--- | :--- |
| `sanitizeHtml` | `true` | Removes HTML tags (like `<script>`) to prevent injection into web views. |
| `removeScriptTags` | `true` | Specifically targets script tags for double-safety. |
| `removeZeroWidthChars` | `true` | Removes invisible characters (e.g., `\u200B`) used to bypass filters. |
| `normalizeMarkdown` | `true` | Collapses excessive newlines to prevent context-window flooding. |

### 2. `piiProtection` (Privacy)
**Redacts sensitive Personal Identifiable Information.**
This layer uses strict regex patterns to mask private data.

| Property | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | Master switch for PII redaction. |
| `maskEmail` | `true` | Replaces emails with `[EMAIL_REDACTED]`. |
| `maskPhone` | `true` | Replaces phone numbers with `[PHONE_REDACTED]`. |
| `maskCreditCard` | `true` | Replaces potential credit card numbers with `[CARD_REDACTED]`. |
| `maskSSN` | `true` | Replaces US Social Security Numbers with `[SSN_REDACTED]`. |
| `maskIP` | `true` | Replaces IPv4 addresses with `[IP_REDACTED]`. |

### 3. `promptInjectionProtection` (Guard)
**Prevents Jailbreaks and System Override attempts.**
This layer uses heuristics and blocklists to stop users from hijacking the model.

| Property | Default | Description |
| :--- | :--- | :--- |
| `blockPhrases` | `['ignore previous...', 'act as system'...]` | Array of phrases that trigger an immediate flag. |
| `separateSystemPrompts` | `true` | (Internal) Logical separation flag to ensure system instructions aren't overridden. |
| `multiTurnSanityCheck` | `true` | Checks for pattern repetition often found in brute-force attacks. |

### 4. `dbProtection` (Vault)
**Prevents SQL Injection for Agentic Tools.**
Essential if your LLM has access to a database tool.

| Property | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` | Master switch for DB checks. |
| `mode` | `'read-only'` | If `'read-only'`, ANY query that isn't `SELECT` is blocked. |
| `forbiddenStatements` | `['DROP', 'DELETE'...]` | Specific keywords that are blocked even in read-write mode. |
| `allowedStatements` | `['SELECT']` | Whitelist of allowed statement starts. |

### 5. `rateLimitingAndResourceControl` (Sentry)
**Prevents Denial of Service (DoS) via Token Consumption.**
Ensures prompts don't exceed reasonable complexity limits.

| Property | Default | Description |
| :--- | :--- | :--- |
| `maxTokensPerPrompt` | `1500` | Flags prompts that are too long. |
| `preventRecursivePrompts` | `true` | Detects logical loops in prompt structures. |

### 6. `outputValidation` (Validator)
**Checks the Model's Output (Optional).**
Ensures the AI doesn't generate malicious code or leak data.

| Property | Default | Description |
| :--- | :--- | :--- |
| `validateAgainstRules` | `true` | General rule validation. |
| `blockMaliciousCommands` | `true` | Scans output for `rm -rf` style commands. |
| `checkPII` | `true` | Re-checks output for PII leakage. |

---

## ⚙️ Advanced Configuration

You can customize every layer by passing a nested configuration object.

```typescript
const onion = new OnionAI({
  // Customize Sanitizer
  inputSanitization: {
    sanitizeHtml: false, // Allow HTML
    removeZeroWidthChars: true
  },
  
  // Customize PII
  piiProtection: {
    enabled: true,
    maskEmail: true,
    maskPhone: false // Allow phone numbers
  },
  
  // Customize Rate Limits
  rateLimitingAndResourceControl: {
    maxTokensPerPrompt: 5000 // Allow larger prompts
  }
});
```

---

## 🔌 Middleware Integration

### Express / Connect
Automatically sanitize `req.body` before it hits your handlers.

```typescript
import { OnionAI, onionRing } from 'onion-ai';
const onion = new OnionAI({ preventPromptInjection: true });

// Apply middleware
// Checks `req.body.prompt` by default
app.post('/chat', onionRing(onion, { promptField: 'body.prompt' }), (req, res) => {
    // Input is now sanitized!
    const cleanPrompt = req.body.prompt;
    
    // Check for threats detected during sanitation
    if (req.onionThreats?.length > 0) {
       console.warn("Blocked:", req.onionThreats);
       return res.status(400).json({ error: "Unsafe input" });
    }
    
    // ... proceed
});
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

## 📄 License

MIT © [Himanshu Mamgain](https://github.com/himanshu-mamgain)