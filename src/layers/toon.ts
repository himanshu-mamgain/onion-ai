
export interface ToonSchema {
    version: "1.0";
    type: "safe_prompt";
    data: {
        content: string;
        riskScore: number;
        threats: string[];
    };
    metadata: {
        timestamp: string;
        signature: string; // specialized hash
    }
}

export class ToonConverter {
    static convert(content: string, riskScore: number, threats: string[]): string {
        const toonObj: ToonSchema = {
            version: "1.0",
            type: "safe_prompt",
            data: {
                content,
                riskScore,
                threats
            },
            metadata: {
                timestamp: new Date().toISOString(),
                signature: ToonConverter.hash(content)
            }
        };
        return JSON.stringify(toonObj, null, 2);
    }

    private static hash(str: string): string {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }
}
