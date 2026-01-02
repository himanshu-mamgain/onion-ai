
import { Privacy } from '../src/layers/privacy';

describe('Privacy Layer Restoration', () => {
    let privacy: Privacy;

    beforeEach(() => {
        privacy = new Privacy({
            enabled: true,
            maskEmail: true,
            maskPhone: true,
            reversible: true,
            custom: [],
            locale: ['US'],
            maskCreditCard: true,
            maskSSN: true,
            maskIP: true,
            detectSecrets: true
        });
    });

    test('should restore redacted email', () => {
        const input = "Contact admin@example.com for help.";
        const result = privacy.anonymize(input);

        // Assert it was redacted
        expect(result.sanitizedValue).not.toContain("admin@example.com");
        expect(result.sanitizedValue).toContain("{{EMAIL_1}}");
        expect(result.metadata.piiMap).toBeDefined();

        // Restore
        const restored = privacy.restore(result.sanitizedValue!, result.metadata.piiMap);
        expect(restored).toBe(input);
    });

    test('should restore multiple items', () => {
        const input = "Email: a@b.com, Phone: 555-0100";
        const result = privacy.anonymize(input);

        expect(result.metadata.piiMap).toBeDefined();
        const restored = privacy.restore(result.sanitizedValue!, result.metadata.piiMap);
        expect(restored).toBe(input);
    });

    test('should handle non-reversible config gracefully', () => {
        const pNonRev = new Privacy({
            enabled: true,
            reversible: false,
            locale: ['US'],
            maskEmail: true,
            maskPhone: true,
            maskCreditCard: true,
            maskSSN: true,
            maskIP: true,
            detectSecrets: true,
            custom: []
        });
        const result = pNonRev.anonymize("test@example.com");

        // Map should be undefined
        expect(result.metadata.piiMap).toBeUndefined();

        // Restore should just return input if map missing
        const restored = pNonRev.restore(result.sanitizedValue!, {} as any);
        expect(restored).toBe(result.sanitizedValue);
    });
});
