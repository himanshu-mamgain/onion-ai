
import { SignatureEngine } from '../src/layers/signature';

describe('Signature Stripping', () => {
    let signature: SignatureEngine;
    const SECRET = "12345678901234567890123456789012"; // 32 chars

    beforeEach(() => {
        signature = new SignatureEngine({
            secret: SECRET,
            mode: 'steganography'
        });
    });

    test('should strip invisible signature', () => {
        const content = "This is important content.";
        const signed = signature.sign(content, { user: "test" });

        expect(signed.content).not.toBe(content);
        expect(signed.content.length).toBeGreaterThan(content.length);

        const stripped = signature.strip(signed.content);
        expect(stripped).toBe(content);
    });

    test('should return original content if no signature found', () => {
        const content = "Clean content";
        const stripped = signature.strip(content);
        expect(stripped).toBe(content);
    });
});
