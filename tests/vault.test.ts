import { Vault } from '../src/layers/vault';

describe('Vault Layer (DB Protection)', () => {
    let vault: Vault;

    beforeEach(() => {
        vault = new Vault({
            enabled: true,
            mode: 'read-only',
            allowedStatements: ['SELECT'],
            forbiddenStatements: ['DROP', 'DELETE', 'INSERT', 'ALTER']
        });
    });

    test('should detect forbidden statements', () => {
        const input = 'DROP TABLE users';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Forbidden SQL statement detected: DROP');
    });

    test('should enforce read-only mode', () => {
        const input = 'UPDATE users SET name = "admin"';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats).toContain('Non-SELECT query detected in read-only mode');
    });

    test('should detect SQL injection markers', () => {
        const input = "SELECT * FROM users WHERE name = 'admin' --";
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(false);
        expect(result.threats.some(t => t.includes('Potential SQL injection marker'))).toBe(true);
    });

    test('should allow safe SELECT queries', () => {
        const input = 'SELECT * FROM products WHERE id = 1';
        const result = vault.checkSQL(input);
        expect(result.safe).toBe(true);
    });
});
