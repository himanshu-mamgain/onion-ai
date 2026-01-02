
import { OnionAI } from '../src';
// We need to use require because CircuitBreaker is exported as a named export from the re-export
const OnionLib = require('../src');

describe('Package Exports', () => {
    test('should export OnionAI class', () => {
        expect(OnionLib.OnionAI).toBeDefined();
    });

    test('should export CircuitBreaker class', () => {
        expect(OnionLib.CircuitBreaker).toBeDefined();
    });

    test('should export Privacy class', () => {
        expect(OnionLib.Privacy).toBeDefined();
    });

    test('should export Guard class', () => {
        expect(OnionLib.Guard).toBeDefined();
    });

    test('should have public access to privacy layer on instance', () => {
        const onion = new OnionLib.OnionAI();
        expect(onion.privacy).toBeDefined();
        // Check if we can access a method
        expect(typeof onion.privacy.anonymize).toBe('function');
    });
});
