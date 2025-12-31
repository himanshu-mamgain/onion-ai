import { OnionConfig, OnionConfigSchema, OnionInputConfig, SecurityResult, SimpleOnionConfig } from './config';
import { Sanitizer } from './layers/sanitizer';
import { Guard } from './layers/guard';
import { Sentry } from './layers/sentry';
import { Vault } from './layers/vault';
import { Validator } from './layers/validator';
import { Enhancer } from './layers/enhancer';
import { Privacy } from './layers/privacy';

// Helper to determine return type
export interface SafePromptResult {
    output: string;
    threats: string[];
    safe: boolean;
    metadata?: any;
}

export class OnionAI {
    private config: OnionConfig;
    private simpleConfig?: SimpleOnionConfig;
    private sanitizer: Sanitizer;
    private guard: Guard;
    private sentry: Sentry;
    private vault: Vault;
    private validator: Validator;
    private enhancer: Enhancer;
    private privacy: Privacy;

    constructor(config: OnionInputConfig | SimpleOnionConfig = {}) {
        // Handle Simple Configuration
        let finalConfig: OnionInputConfig = {};

        if (this.isSimpleConfig(config)) {
            this.simpleConfig = config; // Store reference for callbacks
            finalConfig = {
                dbProtection: { enabled: config.dbSafe ?? false },
                promptInjectionProtection: {
                    // Defaults will apply unless customized deeply
                },
                enhance: { enabled: config.enhance ?? false },
                loggingMonitoringAndAudit: { logRequests: config.debug ?? false },
                piiProtection: { enabled: config.piiSafe ?? false }
            };
        } else {
            finalConfig = config as OnionInputConfig;
        }

        this.config = OnionConfigSchema.parse(finalConfig);

        // Initialize Layers
        this.sanitizer = new Sanitizer(this.config.inputSanitization);
        this.guard = new Guard(this.config.promptInjectionProtection);
        this.sentry = new Sentry(this.config.rateLimitingAndResourceControl);
        this.vault = new Vault(this.config.dbProtection);
        this.validator = new Validator(this.config.outputValidation);
        this.enhancer = new Enhancer(this.config.enhance);
        this.privacy = new Privacy(this.config.piiProtection);
    }

    private isSimpleConfig(config: any): config is SimpleOnionConfig {
        return 'dbSafe' in config || 'enhance' in config || 'preventPromptInjection' in config || 'onWarning' in config || 'piiSafe' in config;
    }

    /**
     * The main entry point for securing prompts.
     * Sanitizes, checks for threats, optionally enhances, and returns the usable string.
     * 
     * @param prompt The user input
     * @param onWarning Optional callback for specific calls. If configured globally, both will be called.
     * @returns The "best possible" safe string. If threats are found, it tries to scrub them or returns the sanitized version.
     */
    async sanitize(prompt: string, onWarning?: (threats: string[]) => void): Promise<string> {
        // 1. Secure (Sanitize + Guard + Vault)
        const secLikelihood = await this.securePrompt(prompt);

        if (!secLikelihood.safe && secLikelihood.threats.length > 0) {
            // Trigger Callbacks
            if (this.simpleConfig?.onWarning) {
                this.simpleConfig.onWarning(secLikelihood.threats);
            }
            if (onWarning) {
                onWarning(secLikelihood.threats);
            }
        }

        // 2. Enhance (if enabled)
        // We always try to enhance the output we have, even if it had warnings (as long as it wasn't empty)
        const output = this.enhancer.enhance(secLikelihood.output);

        return output;
    }

    /**
     * Internal/Advanced method: Step 1 Secure
     * Clean, sanitize, and secure the prompt.
     */
    async securePrompt(prompt: string): Promise<SafePromptResult> {
        const threats: string[] = [];
        let sanitizedPrompt = prompt;

        // 1. Sanitization (XSS / Hidden chars)
        const sanResult = this.sanitizer.validate(prompt);
        sanitizedPrompt = sanResult.sanitizedValue || prompt;

        // 1.5 PII Redaction
        const piiResult = this.privacy.anonymize(sanitizedPrompt);
        sanitizedPrompt = piiResult.sanitizedValue || sanitizedPrompt;
        if (!piiResult.safe) threats.push(...piiResult.threats);

        // 2. Prompt Injection (Firewall)
        // Only run if configured enabled (defaults true)
        const guardResult = this.guard.check(sanitizedPrompt);
        if (!guardResult.safe) threats.push(...guardResult.threats);

        // 3. DB Guard
        if (this.config.dbProtection.enabled) {
            const vaultResult = this.vault.checkSQL(sanitizedPrompt);
            if (!vaultResult.safe) threats.push(...vaultResult.threats);
        }

        // 4. Resource Control (Rate limits check excluded for stateless call, but Token Check relevant)
        const tokenCheck = this.sentry.checkTokenCount(sanitizedPrompt);
        if (!tokenCheck.safe) threats.push(...tokenCheck.threats);

        return {
            output: sanitizedPrompt,
            threats,
            safe: threats.length === 0,
            metadata: {
                estimatedTokens: tokenCheck.metadata?.estimatedTokens
            }
        };
    }

    /**
     * Advanced: Secure & Enhance with full detail return
     * Secure the prompt AND prepare it for AI execution (structuring, system prompts).
     * @returns Only the output string if safe, or throws/returns null? 
     * The user example shows: const enhanced = onion.secureAndEnhancePrompt("..."); console.log(enhanced.output);
     * So it returns a similar object.
     */
    async secureAndEnhancePrompt(prompt: string): Promise<SafePromptResult> {
        // First secure it
        const securityResult = await this.securePrompt(prompt);

        // Then enhance it
        const enhancedText = this.enhancer.enhance(securityResult.output);

        return {
            ...securityResult,
            output: enhancedText
        };
    }

    /**
     * Optional: Output Validation (Legacy support / Standalone)
     */
    async secureResponse(response: string): Promise<SecurityResult> {
        return this.validator.validateOutput(response);
    }
}

export * from './config';
export * from './middleware';

