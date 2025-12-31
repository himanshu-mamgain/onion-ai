import { OnionAI } from './index';
import { SimpleOnionConfig, OnionInputConfig } from './config';

export interface OnionMiddlewareOptions {
    /** Configuration for the OnionAI instance */
    config?: SimpleOnionConfig | OnionInputConfig;

    /** The key in req.body to secure. Default is "prompt". */
    fieldName?: string;

    /** 
     * If true, sends a 400 response when threats are detected. 
     * If false, attaches threats to `req.onionThreats` and proceeds.
     * Default: true
     */
    blockOnThreats?: boolean;

    /** Custom error handler. If provided, responsible for sending the response. */
    errorHandler?: (res: any, threats: string[]) => void;
}

/**
 * Express/Connect compatible middleware for OnionAI.
 * Automatically sanitizes and checks prompts in the request body.
 * 
 * Usage:
 * app.use(onionMiddleware({ config: { debug: true } }));
 * 
 * Or for specific route:
 * app.post('/chat', onionMiddleware({ fieldName: 'userQuery' }), chatHandler);
 */
export const onionMiddleware = (options: OnionMiddlewareOptions = {}) => {
    const onion = new OnionAI(options.config);
    const field = options.fieldName || 'prompt';
    const shouldBlock = options.blockOnThreats ?? true;

    return async (req: any, res: any, next: any) => {
        // Ensure body exists
        if (!req.body) {
            return next();
        }

        const input = req.body[field];

        if (!input || typeof input !== 'string') {
            return next(); // Ignore if target field is missing or not a string
        }

        try {
            // Using securePrompt to get detailed status (we don't run Enhancer in middleware usually, just security)
            const result = await onion.securePrompt(input);

            if (!result.safe) {
                // Attach threats to request regardless of blocking policy (logs/debugging)
                req.onionThreats = result.threats;

                if (shouldBlock) {
                    if (options.errorHandler) {
                        return options.errorHandler(res, result.threats);
                    }

                    // Default Error Response
                    if (typeof res.status === 'function') {
                        return res.status(400).json({
                            error: 'Security Alert: Potentially malicious content detected.',
                            threats: result.threats,
                            code: 'ONION_BLOCK'
                        });
                    } else {
                        // Basic support for non-express or mock objects
                        res.statusCode = 400;
                        res.end(JSON.stringify({ error: 'Security Alert', threats: result.threats }));
                        return;
                    }
                }
            }

            // Replace the input with the sanitized/redacted version
            req.body[field] = result.output;

            // Attach metadata
            req.onionSafe = result.safe;
            req.onionMetadata = result.metadata;

            next();
        } catch (error) {
            console.error("OnionAI Middleware Error:", error);
            next(error);
        }
    };
};
