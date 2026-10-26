import test from 'node:test';
import assert from 'node:assert/strict';
import {scanTextForSecrets} from '../scripts/scan-secrets.mjs';

test('secret scanner detects representative credential forms',()=>{
 assert.deepEqual(scanTextForSecrets(['-----BEGIN','PRIVATE KEY-----'].join(' ')),['private key']);
 assert.deepEqual(scanTextForSecrets(['AK','IA','ABCDEFGHIJKLMNOP'].join('')),['AWS access key']);
 assert.deepEqual(scanTextForSecrets(['client_','secret=',"'0123456789abcdef'"].join('')),['credential assignment']);
});

test('secret scanner ignores placeholders and ordinary engine text',()=>{
 assert.deepEqual(scanTextForSecrets('BANK_API_KEY is forbidden in CI; use a secret name only.'),[]);
 assert.deepEqual(scanTextForSecrets('synthetic tenant and fake payment reference'),[]);
});
