import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity,createRolePolicy} from '../src/identity.mjs';
import {ConsentLedger} from '../src/consent-ledger.mjs';
import {PolicyGateway,createGatewayPolicy} from '../src/policy-gateway.mjs';

const now=4_000_000;
const identityFor=async(overrides={})=>authenticateIdentity({credential:'valid',now},async()=>({verified:true,tenantId:'tenant_alpha',issuer:'https://identity.example',subject:'operator-7',authenticatedAt:now-1_000,expiresAt:now+60_000,authenticationMethods:['password','webauthn'],...overrides}));
const rolePolicy=createRolePolicy([{name:'operator',permissions:['accounts:read','payments:prepare']}]);
const policy=createGatewayPolicy({version:'policy-v1',rules:[{action:'accounts.read',permission:'accounts:read',consentScope:'accounts:read'},{action:'payments.prepare',permission:'payments:prepare',consentScope:'payments:prepare',requiresMfa:true}]});
const assignment=(overrides={})=>({tenantId:'tenant_alpha',issuer:'https://identity.example',subject:'operator-7',role:'operator',validFrom:now-10_000,validUntil:now+10_000,revoked:false,...overrides});

test('allows only when tenant, role, MFA and consent evidence satisfy an exact rule',async()=>{
 const identity=await identityFor();
 const consentLedger=new ConsentLedger();
 consentLedger.grant(identity,{consentId:'consent-1',scopes:['payments:prepare'],purpose:'customer-request',policyVersion:'consent-v1',expiresAt:now+30_000,requestId:'grant-1',now});
 const decision=new PolicyGateway({policy,rolePolicy}).decide({identity,action:'payments.prepare',resourceTenantId:'tenant_alpha',assignments:[assignment()],consentLedger,consentId:'consent-1',now});
 assert.equal(decision.allow,true);assert.equal(decision.reason,'POLICY_ALLOWED');assert.equal(decision.policyVersion,'policy-v1');assert.deepEqual(decision.roles,['operator']);assert.equal(Object.isFrozen(decision),true);
});

test('denies unknown actions and cross-tenant resources without wildcard fallback',async()=>{
 const identity=await identityFor(),gateway=new PolicyGateway({policy,rolePolicy});
 assert.equal(gateway.decide({identity,action:'accounts.export',resourceTenantId:'tenant_alpha',assignments:[assignment()],now}).reason,'NO_POLICY_RULE');
 assert.equal(gateway.decide({identity,action:'accounts.read',resourceTenantId:'tenant_beta',assignments:[assignment()],now}).reason,'TENANT_DENIED');
});

test('denies forged, expired, stale-MFA and inactive-role evidence',async()=>{
 const identity=await identityFor(),gateway=new PolicyGateway({policy,rolePolicy});
 assert.equal(gateway.decide({identity:{...identity},action:'accounts.read',resourceTenantId:'tenant_alpha',assignments:[assignment()],now}).reason,'IDENTITY_UNVERIFIED');
 assert.equal(gateway.decide({identity,action:'accounts.read',resourceTenantId:'tenant_alpha',assignments:[assignment()],now:now+60_000}).reason,'IDENTITY_EXPIRED');
 const stale=await identityFor({authenticatedAt:now-300_001});
 assert.equal(gateway.decide({identity:stale,action:'payments.prepare',resourceTenantId:'tenant_alpha',assignments:[assignment()],now}).reason,'MFA_REQUIRED');
 assert.equal(gateway.decide({identity,action:'accounts.read',resourceTenantId:'tenant_alpha',assignments:[assignment({revoked:true})],now}).reason,'ROLE_DENIED');
});

test('denies missing or failing consent evidence',async()=>{
 const identity=await identityFor(),gateway=new PolicyGateway({policy,rolePolicy});
 const base={identity,action:'accounts.read',resourceTenantId:'tenant_alpha',assignments:[assignment()],now};
 assert.equal(gateway.decide(base).reason,'CONSENT_REQUIRED');
 const consentLedger=new ConsentLedger();
 consentLedger.grant(identity,{consentId:'consent-1',scopes:['accounts:read'],purpose:'customer-request',policyVersion:'consent-v1',expiresAt:now+30_000,requestId:'grant-1',now});
 consentLedger.revoke(identity,{consentId:'consent-1',expectedVersion:1,reason:'customer-request',requestId:'revoke-1',now:now+1});
 assert.equal(gateway.decide({...base,consentLedger,consentId:'consent-1'}).reason,'CONSENT_DENIED');
 class ForgedConsentLedger extends ConsentLedger {permits(){return true;}}
 assert.equal(gateway.decide({...base,consentLedger:new ForgedConsentLedger(),consentId:'consent-1'}).reason,'CONSENT_DENIED');
});

test('policy compilation rejects ambiguity and freezes rules',()=>{
 assert.throws(()=>createGatewayPolicy({version:'v1',rules:[]}),/rule/);
 assert.throws(()=>createGatewayPolicy({version:'v1',rules:[{action:'read',permission:'read'},{action:'read',permission:'write'}]}),/unique/);
 assert.throws(()=>createGatewayPolicy({version:'v1',rules:[{action:'*',permission:'read'}]}),/Action/);
 assert.throws(()=>new PolicyGateway({policy:Object.freeze({version:'forged',rules:Object.freeze({})}),rolePolicy}),/Compiled gateway/);
 assert.throws(()=>{policy.rules['accounts.read'].permission='admin';},TypeError);
});
