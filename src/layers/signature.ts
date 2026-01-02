import * as crypto from 'crypto';

export interface SignatureConfig {
    /**
     * Secret key for encryption and HMAC. 
     * Must be at least 32 characters for security.
     */
    secret: string;

    /**
     * mode:
     * - 'none': Do nothing
     * - 'hmac': Return separated signature
     * - 'steganography': Embed invisible payload
     * - 'dual': Embed invisible payload AND return HMAC
     */
    mode?: 'none' | 'hmac' | 'steganography' | 'dual';
}

export interface VerificationResult {
    isValid: boolean;
    payload?: any;
    timestamp?: number;
    error?: string;
}

/**
 * Handles Cryptographic Signatures and Steganographic Watermarking
 */
export class SignatureEngine {
    private config: SignatureConfig;
    private secret: string;
    private readonly ALGORITHM = 'aes-256-gcm';
    private readonly ZW_ZERO = '\u200B'; // Zero Width Space
    private readonly ZW_ONE = '\u200C';  // Zero Width Non-Joiner
    private readonly HEADER = '\u200D';  // Zero Width Joiner (Start Marker)

    constructor(config: SignatureConfig) {
        if (!config.secret || config.secret.length < 32) {
            throw new Error("Signature secret must be at least 32 characters long.");
        }
        this.secret = config.secret;
        this.config = config;
    }

    /**
     * Signs or Embeds data into the content.
     * @param content The text to sign
     * @param payload Optional JSON data to embed (max 200 chars for steno)
     */
    sign(content: string, payload: object = {}): { content: string; signature?: string } {
        const timestamp = Date.now();
        const data = { ...payload, t: timestamp }; // Embed short timestamp

        let signedContent = content;
        let signature: string | undefined;

        // 1. Embed Steganography if requested
        // Embeds Encrypted payload invisibly at the end of the content
        if (this.mode === 'steganography' || this.mode === 'dual') {
            const hiddenPayload = this.embed(JSON.stringify(data));
            signedContent = content + hiddenPayload;
        }

        // 2. Generate HMAC if requested
        // Signs the FINAL content (including hidden chars if any)
        if (this.mode === 'hmac' || this.mode === 'dual') {
            signature = this.generateHMAC(signedContent);
        }

        return { content: signedContent, signature };
    }

    /**
     * Verifies HMAC signature.
     */
    verifyHMAC(content: string, signature: string): boolean {
        const expected = this.generateHMAC(content);
        return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
    }

    /**
     * Extracts and potentially decrypts invisible payload.
     */
    extract(content: string): VerificationResult {
        try {
            // 1. Find the watermark section (Scan from end)
            // Our pattern starts with HEADER char (\u200D)
            const parts = content.split(this.HEADER);
            if (parts.length < 2) return { isValid: false, error: "No signature watermark detected" };

            // The last part implies the potential watermark payload
            const rawHidden = parts[parts.length - 1];

            // 2. Decode Binary (Zero Width -> Bits)
            const encryptedHex = this.decodeBits(rawHidden);
            if (!encryptedHex) return { isValid: false, error: "Corrupted or invalid signature bits" };

            // 3. Decrypt
            const jsonStr = this.decrypt(encryptedHex);
            const data = JSON.parse(jsonStr);

            return {
                isValid: true,
                payload: data,
                timestamp: data.t
            };

        } catch (err) {
            return { isValid: false, error: "Decryption failed or forged signature" };
        }
    }

    /**
     * Removes the invisible signature from the content.
     * Useful for saving safe content to DB without the heavy watermark.
     */
    strip(content: string): string {
        // Find the last occurrence of the Header
        const lastHeaderIndex = content.lastIndexOf(this.HEADER);
        if (lastHeaderIndex === -1) return content;

        // Verify if the rest comprises only ZW chars
        const potentialSignature = content.slice(lastHeaderIndex + 1);
        const isSignature = /^[​‌]+$/.test(potentialSignature); // Regex for ZW_ZERO and ZW_ONE

        if (isSignature) {
            return content.slice(0, lastHeaderIndex);
        }

        // Fallback: If regex check is complex or we trust the header structure for our own app:
        // Actually, let's strictly check using our defined constants to be safe
        for (const char of potentialSignature) {
            if (char !== this.ZW_ZERO && char !== this.ZW_ONE) {
                return content; // Not a signature
            }
        }

        return content.slice(0, lastHeaderIndex);
    }

    // --- Internal Helpers ---

    private get mode(): string {
        return this.config.mode || 'dual';
    }

    private generateHMAC(text: string): string {
        return crypto.createHmac('sha256', this.secret).update(text).digest('hex');
    }

    // --- Steganography Core ---

    private embed(text: string): string {
        const encrypted = this.encrypt(text);
        const bitString = this.strToBin(encrypted);

        let hidden = this.HEADER; // Start Marker
        for (const bit of bitString) {
            hidden += (bit === '1') ? this.ZW_ONE : this.ZW_ZERO;
        }
        return hidden;
    }

    private decodeBits(zwString: string): string | null {
        let binary = '';
        for (const char of zwString) {
            if (char === this.ZW_ONE) binary += '1';
            else if (char === this.ZW_ZERO) binary += '0';
            else return null; // Non-ZW char found, end of watermark or noise
        }
        return this.binToStr(binary);
    }

    // --- Encryption Core (AES-GCM for Authenticated Encryption) ---

    private encrypt(text: string): string {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(this.ALGORITHM, Buffer.from(this.secret.slice(0, 32)), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag().toString('hex');
        // Format: IV|AuthTag|Encrypted
        return iv.toString('hex') + ':' + authTag + ':' + encrypted;
    }

    private decrypt(text: string): string {
        const [ivHex, authTagHex, encryptedHex] = text.split(':');
        if (!ivHex || !authTagHex || !encryptedHex) throw new Error("Invalid format");

        const decipher = crypto.createDecipheriv(
            this.ALGORITHM,
            Buffer.from(this.secret.slice(0, 32)),
            Buffer.from(ivHex, 'hex')
        );

        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    // --- Binary Helpers ---

    private strToBin(text: string): string {
        return text.split('').map(char =>
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');
    }

    private binToStr(binary: string): string {
        if (binary.length % 8 !== 0) return '';
        const chars = [];
        for (let i = 0; i < binary.length; i += 8) {
            const byte = binary.slice(i, i + 8);
            chars.push(String.fromCharCode(parseInt(byte, 2)));
        }
        return chars.join('');
    }
}
