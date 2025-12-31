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
export function onionRing(onion: OnionAI, options: { promptField?: string; outputField?: string } = {}) {
    const promptPath = options.promptField || 'body.prompt';

    return async (req: any, res: any, next: MiddlewareNext) => {
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

                if (!safePrompt && req.onionThreats?.length > 0) {
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
function getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
}

function setNestedValue(obj: any, path: string, value: any): void {
    const parts = path.split('.');
    const last = parts.pop();
    const target = parts.reduce((acc, part) => acc && acc[part], obj);
    if (target && last) {
        target[last] = value;
    }
}
