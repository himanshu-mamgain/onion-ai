import { OnionAI } from './index';
// Helper type for generic middleware signature
type MiddlewareNext = () => Promise<void> | void;

/**
 * Creates an Express/Connect style middleware for OnionAI.
 * 
 * @param onion - The OnionAI instance
 * @param options - Configuration for mapping request body fields
 * @returns Middleware function
 * 
 * @example
 * app.use(onionRing(new OnionAI(), { promptField: 'body.query' }));
 */
// Minimal interface compatible with Express/Fastify Request objects
interface MinimalRequest extends Record<string, any> {
    body?: any;
    query?: any;
    params?: any;
    onionThreats?: string[];
}

export function onionRing(onion: OnionAI, options: { promptField?: string; outputField?: string } = {}) {
    const promptPath = options.promptField || 'body.prompt';

    // Using generic T for Request to allow users to pass their own types if needed, defaulting to MinimalRequest
    return async <T extends MinimalRequest>(req: T, res: unknown, next: MiddlewareNext) => {
        try {
            // 1. Resolve prompt from request
            const prompt = getNestedValue(req, promptPath);

            if (typeof prompt === 'string') {
                const safePrompt = await onion.sanitize(prompt, (threats) => {
                    // Attach threats to request for logging downstream
                    req.onionThreats = threats;
                });

                // 2. Replace the prompt in the request body with the sanitized version
                setNestedValue(req, promptPath, safePrompt);

                if (!safePrompt && req.onionThreats && req.onionThreats.length > 0) {
                    // Option: Block request entirely if heavily compromised? 
                    // For now, we pass the empty/sanitized string. 
                    // Users can check req.onionThreats to decide to 400.
                }
            }

            next();
        } catch (error) {
            console.error('[OnionAI Middleware Error]', error);
            next();
        }
    };
}

// Helpers
function getNestedValue(obj: Record<string, any>, path: string): unknown {
    return path.split('.').reduce((acc, part) => (acc && typeof acc === 'object' ? acc[part] : undefined), obj);
}

function setNestedValue(obj: Record<string, any>, path: string, value: any): void {
    const parts = path.split('.');
    const last = parts.pop();
    const target = parts.reduce((acc, part) => (acc && typeof acc === 'object' ? acc[part] : undefined), obj);
    if (target && last) {
        target[last] = value;
    }
}
