
export interface UserPromptOptions {
    content?: string; // The core user input/query
    context?: string; // Background info, RAG context, or previous turns
    instruction?: string; // Specific instruction for this turn (e.g. "Summarize this")
}

export class UserPrompt {
    private _content: string = "";
    private _context: string = "";
    private _instruction: string = "";

    constructor(options?: string | UserPromptOptions) {
        if (typeof options === 'string') {
            this._content = options;
        } else if (options) {
            if (options.content) this._content = options.content;
            if (options.context) this._context = options.context;
            if (options.instruction) this._instruction = options.instruction;
        }
    }

    /**
     * Sets the main content of the user prompt (the query).
     */
    content(text: string): this {
        this._content = text;
        return this;
    }

    /**
     * Adds context (e.g. RAG data, conversation history summary).
     */
    context(text: string): this {
        this._context = text;
        return this;
    }

    /**
     * Adds specific instruction for handling this prompt.
     * distinct from System Prompt, this is a user-level instruction.
     */
    instruction(text: string): this {
        this._instruction = text;
        return this;
    }

    /**
     * Compiles the prompt into the specified format.
     */
    build(format: 'markdown' | 'toon' | 'xml' | 'json' = 'markdown'): string {
        // TOON (The Onion Object Notation)
        if (format === 'toon' || format === 'json') {
            const toonObj: any = {
                type: "user_input",
                content: this._content
            };
            if (this._context) toonObj.context = this._context;
            if (this._instruction) toonObj.instruction = this._instruction;
            
            return JSON.stringify(toonObj, null, 2);
        }

        // XML (Claude/Anthropic style)
        if (format === 'xml') {
            let output = "";
            if (this._context) output += `<context>\n${this._context}\n</context>\n`;
            if (this._instruction) output += `<instruction>\n${this._instruction}\n</instruction>\n`;
            output += `<user_query>\n${this._content}\n</user_query>`;
            return output;
        }

        // Default Markdown
        let parts: string[] = [];
        if (this._context) parts.push(`### Context\n${this._context}`);
        if (this._instruction) parts.push(`### Instruction\n${this._instruction}`);
        parts.push(this._content);

        return parts.join('\n\n');
    }

    /**
     * Alias for build('markdown')
     */
    toString(): string {
        return this.build('markdown');
    }
}
