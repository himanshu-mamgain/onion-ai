import { Sentry } from '../src/layers/sentry';

describe('Sentry Layer (Resource Control)', () => {
    let sentry: Sentry;

    beforeEach(() => {
        sentry = new Sentry({
            maxTokensPerPrompt: 10,
            maxTokensPerResponse: 100,
            maxTokensPerMinute: 1000,
            maxRequestsPerMinute: 2,
            preventRecursivePrompts: true
        });
    });

    test('should allow prompts within token limit', () => {
        const input = 'Short prompt';
        const result = sentry.checkTokenCount(input);
        expect(result.safe).toBe(true);
    });

    test('should block prompts exceeding token limit', () => {
        const input = 'This is a very long prompt that should definitely exceed the small limit we set of 10 tokens estimated.';
        const result = sentry.checkTokenCount(input);
        expect(result.safe).toBe(false);
        expect(result.threats[0]).toContain('exceeds max token limit');
    });

    test('should enforce rate limits', () => {
        // 1st request
        expect(sentry.checkRateLimit().safe).toBe(true);
        // 2nd request
        expect(sentry.checkRateLimit().safe).toBe(true);
        // 3rd request (should fail, max 2)
        const result = sentry.checkRateLimit();
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Rate limit exceeded (Max requests per minute)');
    });
});
