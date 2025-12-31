import { OnionConfig, OnionConfigSchema, OnionInputConfig, SecurityResult } from './config';
import { Sanitizer } from './layers/sanitizer';
import { Guard } from './layers/guard';
import { Sentry } from './layers/sentry';
import { Vault } from './layers/vault';
import { Validator } from './layers/validator';

export class OnionAI {
    private config: OnionConfig;
    private sanitizer: Sanitizer;
    private guard: Guard;
    private sentry: Sentry;
    private vault: Vault;
    private validator: Validator;

    constructor(config: OnionInputConfig = {}) {
        this.config = OnionConfigSchema.parse(config);
        this.sanitizer = new Sanitizer(this.config.inputSanitization);
        this.guard = new Guard(this.config.promptInjectionProtection);
        this.sentry = new Sentry(this.config.rateLimitingAndResourceControl);
        this.vault = new Vault(this.config.dbProtection);
        this.validator = new Validator(this.config.outputValidation);
    }

    /**
     * Processes a prompt through all input security layers
     */
    async securePrompt(prompt: string, userId?: string, modelUsed?: string): Promise<SecurityResult & { sanitizedPrompt: string }> {
        const threats: string[] = [];
        let sanitizedPrompt = prompt;

        // 1. Rate Limiting / Resource Control
        const rateLimit = this.sentry.checkRateLimit();
        if (!rateLimit.safe) threats.push(...rateLimit.threats);

        const tokenCheck = this.sentry.checkTokenCount(prompt);
        if (!tokenCheck.safe) threats.push(...tokenCheck.threats);

        // 2. Auth & Access Control
        if (this.config.authenticationAndAccessControl.requireAuth && !userId) {
            threats.push("Authentication required but no UserID provided");
        }

        if (modelUsed && !this.config.authenticationAndAccessControl.allowedModels.includes(modelUsed)) {
            threats.push(`Model "${modelUsed}" is not in the allowed list`);
        }

        // 3. Sanitization
        const sanResult = this.sanitizer.validate(prompt);
        sanitizedPrompt = sanResult.sanitizedValue || prompt;

        // 4. Prompt Injection Protection
        const guardResult = this.guard.check(sanitizedPrompt);
        if (!guardResult.safe) threats.push(...guardResult.threats);

        // 5. DB Protection / SQL Safety
        const vaultResult = this.vault.checkSQL(sanitizedPrompt);
        if (!vaultResult.safe) threats.push(...vaultResult.threats);

        // Logging
        if (this.config.loggingMonitoringAndAudit.logRequests) {
            this.logRequest({
                userId,
                modelUsed,
                prompt: this.config.loggingMonitoringAndAudit.logPrompt ? prompt : '[REDACTED]',
                safe: threats.length === 0,
                threats
            });
        }

        return {
            safe: threats.length === 0,
            threats,
            sanitizedPrompt,
            metadata: {
                estimatedTokens: tokenCheck.metadata?.estimatedTokens
            }
        };
    }

    /**
     * Processes AI response through output security layers
     */
    async secureResponse(response: string): Promise<SecurityResult> {
        const result = this.validator.validateOutput(response);

        if (this.config.loggingMonitoringAndAudit.logResponse) {
            // Log response safety
        }

        return result;
    }

    private logRequest(data: any) {
        console.log(`[OnionAI Audit] ${new Date().toISOString()}:`, JSON.stringify(data, null, 2));
    }
}

export * from './config';
