import { OnionAI } from '../dist/index';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    const onion = new OnionAI({
        preventPromptInjection: true,
        piiSafe: true,
        dbSafe: true,
        enhance: true
    });

    const samplesDir = path.join(__dirname, '../threat-samples');
    const files = fs.readdirSync(samplesDir);

    console.log("=== Running Threat Samples ===\n");

    for (const file of files) {
        const content = fs.readFileSync(path.join(samplesDir, file), 'utf-8');
        console.log(`\n--- Testing: ${file} ---`);
        console.log("Input:", content.trim().substring(0, 50) + "...");

        const result = await onion.sanitize(content, (threats) => {
            console.log("❌ Threats Detected:", threats);
        });

        console.log("✅ Sanitized Output:", result);
    }
}

main();
