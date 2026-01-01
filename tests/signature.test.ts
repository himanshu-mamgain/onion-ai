
import { SignatureEngine } from '../src/layers/signature';
import * as crypto from 'crypto';

// Generate a valid 32-char secret
const SECRET = crypto.randomBytes(32).toString('hex').slice(0, 32);

describe('SignatureEngine', () => {
    let engine: SignatureEngine;

    beforeEach(() => {
        engine = new SignatureEngine({
            secret: SECRET,
            mode: 'dual'
        });
    });

    test('should throw error for short secret', () => {
        expect(() => {
            new SignatureEngine({ secret: 'short' });
        }).toThrow();
    });

    test('should sign content with HMAC', () => {
        const content = "Hello World";
        const result = engine.sign(content, { user: 'test' });

        expect(result.signature).toBeDefined();
        // Verify signature
        const isValid = engine.verifyHMAC(result.content, result.signature!);
        expect(isValid).toBe(true);
    });

    test('should fail HMAC verification on tampered content', () => {
        const content = "Hello World";
        const result = engine.sign(content);
        const isValid = engine.verifyHMAC(result.content + "!", result.signature!);
        expect(isValid).toBe(false);
    });

    test('should embed invisible steganography', () => {
        const content = "Hello World";
        const payload = { userId: 123, role: 'admin' };

        const result = engine.sign(content, payload);

        // Content should look same but length check fails due to invisible chars
        expect(result.content).not.toBe(content);
        expect(result.content.startsWith(content)).toBe(true);

        // Extract
        const extracted = engine.extract(result.content);
        expect(extracted.isValid).toBe(true);
        expect(extracted.payload.userId).toBe(123);
        expect(extracted.payload.role).toBe('admin');
        expect(extracted.timestamp).toBeDefined();
    });

    test('should return invalid for non-signed text', () => {
        const result = engine.extract("Just plain text");
        expect(result.isValid).toBe(false);
    });

    test('should return invalid for tampered steganography', () => {
        const result = engine.sign("Text", { foo: 'bar' });
        // Corrupt bits (remove last char)
        const tampered = result.content.slice(0, -1);

        const extracted = engine.extract(tampered);
        expect(extracted.isValid).toBe(false);
    });
});
