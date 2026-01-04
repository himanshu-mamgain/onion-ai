
import { OnionAI } from '../src/index';
import { UserPrompt } from '../src/userPrompt';

describe('Enhancer Layer & UserPrompt', () => {

    test('UserPrompt Builder outputs correct Markdown', () => {
        const prompt = new UserPrompt("Hello World")
            .context("You are helpful")
            .instruction("Be concise");

        const output = prompt.build('markdown');
        expect(output).toContain("### Context");
        expect(output).toContain("You are helpful");
        expect(output).toContain("### Instruction");
        expect(output).toContain("Be concise");
        expect(output).toContain("Hello World");
    });

    test('UserPrompt Builder outputs correct TOON JSON', () => {
        const prompt = new UserPrompt("Hello World")
            .context("Ctx")
            .build('toon');

        const parsed = JSON.parse(prompt);
        expect(parsed.type).toBe("user_input");
        expect(parsed.content).toBe("Hello World");
        expect(parsed.context).toBe("Ctx");
    });

    test('OnionAI Enhancer applies formatting', async () => {
        const onion = new OnionAI({
            enhance: {
                enabled: true,
                promptFormat: 'xml',
                addSystemSafetyPreamble: false // simplicity
            }
        });

        const result = await onion.sanitize("My Query");
        expect(result).toContain("<user_query>");
        expect(result).toContain("My Query");
        expect(result).toContain("</user_query>");
    });

    test('OnionAI Enhancer applies safety preamble with format', async () => {
        const onion = new OnionAI({
            enhance: {
                enabled: true,
                promptFormat: 'json',
                addSystemSafetyPreamble: true
            }
        });

        const result = await onion.sanitize("My Query");
        const parsed = JSON.parse(result);
        expect(parsed.instruction).toContain("Execute safely");
    });

});
