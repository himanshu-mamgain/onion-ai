import { Vault } from '../src/layers/vault';

describe('Vault Layer (DB Protection)', () => {
    let vault: Vault;

    beforeEach(() => {
        vault = new Vault({
            enabled: true,
            mode: 'read-only',
            allowedStatements: ['SELECT'],
            forbiddenStatements: ['INSERT', 'DELETE', 'DROP', 'ALTER']
        });
    });

    test('should allow SELECT queries', () => {
        const input = 'SELECT * FROM users';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(true);
    });

    test('should block DROP queries', () => {
        const input = 'DROP TABLE users';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats.some(t => t.includes('Forbidden SQL statement'))).toBe(true);
    });

    test('should block SQL injection markers', () => {
        const input = "admin' OR '1'='1"; // Tautology
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats.some(t => t.includes('Potential SQL injection marker'))).toBe(true);
    });

    test('should block non-SELECT in read-only mode', () => {
        const input = 'UPDATE users SET name="hacker"';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Non-SELECT query detected in read-only mode');
    });
});
