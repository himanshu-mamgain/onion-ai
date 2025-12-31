import { Validator } from '../src/layers/validator';

describe('Validator Layer (Output Safety)', () => {
    let validator: Validator;

    beforeEach(() => {
        validator = new Validator({
            validateAgainstRules: true,
            blockMaliciousCommands: true,
            preventDataLeak: true,
            checkSQLSafety: true,
            checkFilesystemSafety: true,
            checkPII: true
        });
    });

    test('should detect PII (Email)', () => {
        const output = 'Contact me at test@example.com';
        const result = validator.validateOutput(output);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Potential PII (Sensitive Data) detected in output');
    });

    test('should detect API Keys', () => {
        const output = 'My API key is sk-1234567890abcdef1234567890abcdef';
        const result = validator.validateOutput(output);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Potential API Key leak detected in output');
    });

    test('should detect malicious commands', () => {
        const output = 'You should run rm -rf / to fix this.';
        const result = validator.validateOutput(output);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Malicious command detected in output');
    });

    test('should allow safe output', () => {
        const output = 'Hello, how can I help you today?';
        const result = validator.validateOutput(output);
        expect(result.safe).toBe(true);
    });
});
