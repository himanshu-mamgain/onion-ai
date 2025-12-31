import { Sanitizer } from '../src/layers/sanitizer';

describe('Sanitizer Layer', () => {
    let sanitizer: Sanitizer;

    beforeEach(() => {
        sanitizer = new Sanitizer({
            sanitizeHtml: true,
            removeScriptTags: true,
            escapeSpecialChars: true,
            removeZeroWidthChars: true,
            normalizeMarkdown: true
        });
    });

    test('should remove script tags', () => {
        const input = 'Hello <script>alert("xss")</script>';
        const result = sanitizer.validate(input);
        expect(result.sanitizedValue).not.toContain('<script>');
        expect(result.sanitizedValue).not.toContain('alert("xss")');
        expect(result.threats.length).toBeGreaterThan(0);
    });

    test('should remove zero-width characters', () => {
        const input = 'Hello\u200BWorld';
        const result = sanitizer.validate(input);
        expect(result.sanitizedValue).toBe('HelloWorld');
        expect(result.threats.length).toBeGreaterThan(0);
    });

    test('should normalize markdown', () => {
        const input = 'Line 1\n\n\nLine 2';
        const result = sanitizer.validate(input);
        expect(result.sanitizedValue).toBe('Line 1\n\nLine 2');
    });

    test('should handle empty input', () => {
        const result = sanitizer.validate('');
        expect(result.safe).toBe(true);
        expect(result.sanitizedValue).toBe('');
    });
});
