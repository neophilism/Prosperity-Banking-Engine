import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity} from '../src/identity.mjs';
import {ConsentLedger} from '../src/consent-ledger.mjs';

const now=3_000_000;
const identityFor=async(tenantId='tenant_alpha',subject='customer-7')=>authenticateIdentity({credential:'valid',now},async()=>({verified:true,tenantId,issuer:'https://identity.example',subject,authenticatedAt:now-1_000,expiresAt:now+600_000,authenticationMethods:['password','webauthn']}));
const grant=(overrides={})=>({consentId:'consent-1',scopes:['accounts:read','profile:read'],purpose:'personal-banker',policyVersion:'policy-v1',expiresAt:now+120_000,requestId:'request-grant-1',now,...overrides});

test('grant records immutable scoped evidence and exact replay is idempotent',async()=>{
 const identity=await identityFor(),ledger=new ConsentLedger();
 const first=ledger.grant(identity,grant()),replay=ledger.grant(identity,grant());
 assert.strictEqual(replay,first);assert.equal(first.type,'GRANTED');assert.equal(first.version,1);assert.deepEqual(first.scopes,['accounts:read','profile:read']);
 assert.equal(ledger.permits(identity,{consentId:'consent-1',scope:'accounts:read',now}),true);
 assert.equal(ledger.permits(identity,{consentId:'consent-1',scope:'payments:execute',now}),false);
 assert.throws(()=>ledger.grant(identity,grant({purpose:'other'})),/different terms/);
 assert.throws(()=>{first.purpose='changed';},TypeError);
});

test('revocation is append-only, exact-versioned and immediately denies use',async()=>{
 const identity=await identityFor(),ledger=new ConsentLedger();ledger.grant(identity,grant());
 assert.throws(()=>ledger.revoke(identity,{consentId:'consent-1',expectedVersion:0,reason:'customer-request',requestId:'request-revoke-1',now:now+1}),/version changed/);
 const revoked=ledger.revoke(identity,{consentId:'consent-1',expectedVersion:1,reason:'customer-request',requestId:'request-revoke-1',now:now+1});
 assert.equal(revoked.type,'REVOKED');assert.equal(revoked.version,2);assert.equal(ledger.permits(identity,{consentId:'consent-1',scope:'accounts:read',now:now+2}),false);
 const history=ledger.history(identity,'consent-1');assert.deepEqual(history.map(event=>event.type),['GRANTED','REVOKED']);assert.deepEqual(history.map(event=>event.sequence),[1,2]);
 assert.strictEqual(ledger.revoke(identity,{consentId:'consent-1',expectedVersion:1,reason:'customer-request',requestId:'request-revoke-1',now:now+50}),revoked);
 assert.throws(()=>ledger.revoke(identity,{consentId:'consent-1',expectedVersion:2,reason:'again',requestId:'request-revoke-2',now:now+2}),/already revoked/);
});

test('tenant, subject, expiry and verifier provenance fail closed',async()=>{
 const owner=await identityFor(),otherTenant=await identityFor('tenant_beta'),otherSubject=await identityFor('tenant_alpha','customer-8'),ledger=new ConsentLedger();ledger.grant(owner,grant());
 assert.equal(ledger.permits(otherTenant,{consentId:'consent-1',scope:'accounts:read',now}),false);
 assert.equal(ledger.permits(otherSubject,{consentId:'consent-1',scope:'accounts:read',now}),false);
 assert.equal(ledger.permits(owner,{consentId:'consent-1',scope:'accounts:read',now:now+120_000}),false);
 assert.throws(()=>ledger.revoke(otherSubject,{consentId:'consent-1',expectedVersion:1,reason:'forged',requestId:'other',now}),/Only the verified/);
 assert.throws(()=>ledger.permits({...owner},{consentId:'consent-1',scope:'accounts:read',now}),/Verified identity/);
 assert.deepEqual(ledger.history(otherTenant,'consent-1'),[]);
});

test('invalid grants and request-key collisions are rejected',async()=>{
 const identity=await identityFor(),ledger=new ConsentLedger();
 assert.throws(()=>ledger.grant(identity,grant({scopes:[]})),/scope/);
 assert.throws(()=>ledger.grant(identity,grant({expiresAt:now})),/future/);
 ledger.grant(identity,grant());
 assert.throws(()=>ledger.grant(identity,grant({consentId:'consent-2'})),/different terms/);
 assert.throws(()=>ledger.grant(identity,grant({requestId:'request-grant-2'})),/already exists/);
});
