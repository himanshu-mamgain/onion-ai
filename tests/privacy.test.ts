import { Privacy } from '../src/layers/privacy';

describe('Privacy Layer (PII Redaction)', () => {
    let privacy: Privacy;

    beforeEach(() => {
        privacy = new Privacy({
            enabled: true,
            maskEmail: true,
            maskPhone: true,
            maskCreditCard: true,
            maskSSN: true,
            maskIP: true,
            detectSecrets: true,
            custom: [],
            reversible: false,
            locale: ['US']
        });
    });

    test('should redact email addresses', () => {
        const input = 'Contact me at test.user@example.com immediately.';
        const result = privacy.anonymize(input);
        expect(result.sanitizedValue).toContain('[EMAIL_REDACTED]');
        expect(result.sanitizedValue).not.toContain('test.user@example.com');
        expect(result.threats).toContain('PII Detected: EMAIL');
    });

    test('should redact phone numbers', () => {
        const input = 'Call 555-555-0199 or (555) 123-4567';
        const result = privacy.anonymize(input);
        expect(result.sanitizedValue).toContain('[PHONE_REDACTED]');
        expect(result.sanitizedValue).not.toContain('555-0199');
    });

    test('should redact IPv4 addresses', () => {
        const input = 'Server IP is 192.168.1.1';
        const result = privacy.anonymize(input);
        expect(result.sanitizedValue).toContain('[IP_REDACTED]');
        expect(result.sanitizedValue).not.toContain('192.168.1.1');
    });

    test('should return safe=true with empty threats for clean input', () => {
        const input = 'Hello world, just normal text.';
        const result = privacy.anonymize(input);
        expect(result.safe).toBe(true);
        expect(result.threats.length).toBe(0);
        expect(result.sanitizedValue).toBe(input);
    });

    test('should detect and redact secrets (API Keys) and assign high risk', () => {
        // Override config for this test if needed, but we can just crea a new instance
        const privacyWithSecrets = new Privacy({
            enabled: true,
            maskEmail: true,
            maskPhone: true,
            maskCreditCard: true,
            maskSSN: true,
            maskIP: true,
            detectSecrets: true,
            custom: [],
            reversible: false,
            locale: ['US']
        });

        const input = 'My OpenAI key is sk-abcdef1234567890abcdef1234567890abcdef123456 and GitHub token is ghp_1234567890abcdef1234567890abcdef36char';
        const result = privacyWithSecrets.anonymize(input);

        expect(result.sanitizedValue).toContain('[SECRET_OPENAI_REDACTED]');
        expect(result.sanitizedValue).toContain('[SECRET_GITHUB_REDACTED]');
        expect(result.threats.some(t => t.includes('CRITICAL'))).toBe(true);
        expect(result.riskScore).toBe(1.0);
    });
});
