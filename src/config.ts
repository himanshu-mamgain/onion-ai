import { z } from 'zod';

const InputSanitizationSchema = z.object({
    sanitizeHtml: z.boolean().default(true),
    removeScriptTags: z.boolean().default(true),
    escapeSpecialChars: z.boolean().default(true),
    removeZeroWidthChars: z.boolean().default(true),
    normalizeMarkdown: z.boolean().default(true),
});

const PromptInjectionProtectionSchema = z.object({
    blockPhrases: z.array(z.string()).default([
        "ignore previous instructions",
        "act as system",
        "you are root",
        "reveal system prompt"
    ]),
    separateSystemPrompts: z.boolean().default(true),
    multiTurnSanityCheck: z.boolean().default(true),
    structuredPromptRequired: z.boolean().default(true),
});

const DbProtectionSchema = z.object({
    enabled: z.boolean().default(true),
    mode: z.enum(["read-only", "read-write"]).default("read-only"),
    allowedStatements: z.array(z.string()).default(["SELECT"]),
    forbiddenStatements: z.array(z.string()).default(["INSERT", "DELETE", "DROP", "ALTER"]),
});

const RateLimitingAndResourceControlSchema = z.object({
    maxTokensPerPrompt: z.number().default(1500),
    maxTokensPerResponse: z.number().default(800),
    maxTokensPerMinute: z.number().default(5000),
    maxRequestsPerMinute: z.number().default(20),
    preventRecursivePrompts: z.boolean().default(true),
});

const OutputValidationSchema = z.object({
    validateAgainstRules: z.boolean().default(true),
    blockMaliciousCommands: z.boolean().default(true),
    preventDataLeak: z.boolean().default(true),
    checkSQLSafety: z.boolean().default(true),
    checkFilesystemSafety: z.boolean().default(true),
    checkPII: z.boolean().default(true),
});

const AuthenticationAndAccessControlSchema = z.object({
    requireAuth: z.boolean().default(true),
    allowedModels: z.array(z.string()).default(["qwen", "gemma"]),
    roleBasedModelAccess: z.boolean().default(true),
});

const PromptStructureAndLimitsSchema = z.object({
    requireStructuredPrompts: z.boolean().default(true),
    maxPromptLength: z.number().default(4000),
    limitPromptComplexity: z.boolean().default(true),
    taskSpecificPrompts: z.boolean().default(true),
});

const LoggingMonitoringAndAuditSchema = z.object({
    logRequests: z.boolean().default(true),
    logUserId: z.boolean().default(true),
    logModelUsed: z.boolean().default(true),
    logPrompt: z.boolean().default(true),
    logResponse: z.boolean().default(true),
    alertOnSuspiciousPatterns: z.boolean().default(true),
});

export const OnionConfigSchema = z.object({
    inputSanitization: InputSanitizationSchema.default({
        sanitizeHtml: true,
        removeScriptTags: true,
        escapeSpecialChars: true,
        removeZeroWidthChars: true,
        normalizeMarkdown: true,
    }),
    promptInjectionProtection: PromptInjectionProtectionSchema.default({
        blockPhrases: ["ignore previous instructions", "act as system", "you are root", "reveal system prompt"],
        separateSystemPrompts: true,
        multiTurnSanityCheck: true,
        structuredPromptRequired: true,
    }),
    dbProtection: DbProtectionSchema.default({
        enabled: true,
        mode: "read-only",
        allowedStatements: ["SELECT"],
        forbiddenStatements: ["INSERT", "DELETE", "DROP", "ALTER"],
    }),
    rateLimitingAndResourceControl: RateLimitingAndResourceControlSchema.default({
        maxTokensPerPrompt: 1500,
        maxTokensPerResponse: 800,
        maxTokensPerMinute: 5000,
        maxRequestsPerMinute: 20,
        preventRecursivePrompts: true,
    }),
    outputValidation: OutputValidationSchema.default({
        validateAgainstRules: true,
        blockMaliciousCommands: true,
        preventDataLeak: true,
        checkSQLSafety: true,
        checkFilesystemSafety: true,
        checkPII: true,
    }),
    authenticationAndAccessControl: AuthenticationAndAccessControlSchema.default({
        requireAuth: true,
        allowedModels: ["qwen", "gemma"],
        roleBasedModelAccess: true,
    }),
    promptStructureAndLimits: PromptStructureAndLimitsSchema.default({
        requireStructuredPrompts: true,
        maxPromptLength: 4000,
        limitPromptComplexity: true,
        taskSpecificPrompts: true,
    }),
    loggingMonitoringAndAudit: LoggingMonitoringAndAuditSchema.default({
        logRequests: true,
        logUserId: true,
        logModelUsed: true,
        logPrompt: true,
        logResponse: true,
        alertOnSuspiciousPatterns: true,
    }),
});

export type OnionConfig = z.infer<typeof OnionConfigSchema>;
export type OnionInputConfig = z.input<typeof OnionConfigSchema>;

export interface SecurityResult {
    safe: boolean;
    threats: string[];
    sanitizedValue?: string;
    metadata?: any;
}
