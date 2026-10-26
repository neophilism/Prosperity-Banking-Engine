import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity,createRolePolicy} from '../src/identity.mjs';
import {PolicyGateway,createGatewayPolicy} from '../src/policy-gateway.mjs';
import {createEvidenceVaultContract,TenantEvidenceVault} from '../src/evidence-vault.mjs';

const now=9_000_000;
const identityFor=async(tenantId='tenant_alpha',subject='operator-9')=>authenticateIdentity({credential:'valid',now},async()=>({verified:true,tenantId,issuer:'https://identity.example',subject,authenticatedAt:now-1_000,expiresAt:now+60_000,authenticationMethods:['workload']}));
const rolePolicy=createRolePolicy([{name:'evidence-operator',permissions:['evidence:read','evidence:write']}]);
const policy=createGatewayPolicy({version:'evidence-policy-v1',rules:[{action:'evidence.read',permission:'evidence:read'},{action:'evidence.write',permission:'evidence:write'}]});
const contract=createEvidenceVaultContract({version:'vault-v1',actions:{read:'evidence.read',write:'evidence.write'}});
const assignmentFor=(tenantId='tenant_alpha',subject='operator-9')=>({tenantId,issuer:'https://identity.example',subject,role:'evidence-operator',validFrom:now-10_000,validUntil:now+10_000,revoked:false});
const vault=()=>new TenantEvidenceVault({contract,gateway:new PolicyGateway({policy,rolePolicy})});
const store=(identity,overrides={})=>({identity,requestId:'request-1',evidenceId:'evidence-1',category:'consent_or_audit_evidence',contentDigest:'a'.repeat(64),keyReference:'object/tenant-alpha/evidence-1',mediaType:'application/pdf',sizeBytes:4096,capturedAt:now-100,source:'synthetic-test',assignments:[assignmentFor(identity.tenantId,identity.subject)],now,...overrides});

test('stores immutable digest metadata and replays exact requests',async()=>{
 const identity=await identityFor(),repository=vault(),first=repository.store(store(identity)),replay=repository.store(store(identity,{now:now+1}));
 assert.strictEqual(replay,first);assert.equal(first.classification,'RESTRICTED');assert.equal(first.tenantId,'tenant_alpha');assert.equal(first.vaultVersion,'vault-v1');assert.equal(Object.isFrozen(first),true);assert.equal(Object.isFrozen(first.producer),true);
 assert.throws(()=>repository.store(store(identity,{contentDigest:'b'.repeat(64)})),/different terms/);
});

test('isolates tenant reads and listings without leaking identifiers',async()=>{
 const alpha=await identityFor(),beta=await identityFor('tenant_beta'),repository=vault(),record=repository.store(store(alpha));
 assert.strictEqual(repository.get({identity:alpha,evidenceId:'evidence-1',assignments:[assignmentFor()],now}),record);
 assert.deepEqual(repository.list({identity:alpha,assignments:[assignmentFor()],now}),[record]);
 assert.deepEqual(repository.list({identity:beta,assignments:[assignmentFor('tenant_beta')],now}),[]);
 assert.throws(()=>repository.get({identity:beta,evidenceId:'evidence-1',assignments:[assignmentFor('tenant_beta')],now}),/does not exist/);
});

test('requires verified active identities and exact policy authorization',async()=>{
 const identity=await identityFor(),repository=vault();
 assert.throws(()=>repository.store(store(identity,{assignments:[]})),/authorization/);
 assert.throws(()=>repository.store(store({...identity})),/Verified identity/);
 assert.throws(()=>repository.store(store(identity,{now:identity.expiresAt})),/Active verified identity/);
});

test('rejects raw evidence, malformed commitments and unsafe bounds',async()=>{
 const identity=await identityFor(),repository=vault();
 assert.throws(()=>repository.store({...store(identity),content:'secret'}),/Raw evidence/);
 assert.throws(()=>repository.store(store(identity,{contentDigest:'ABC'})),/SHA-256/);
 assert.throws(()=>repository.store(store(identity,{sizeBytes:0})),/between/);
 assert.throws(()=>repository.store(store(identity,{capturedAt:now+1})),/no later/);
 assert.throws(()=>createEvidenceVaultContract({version:'v1',actions:{read:'evidence.read',write:'evidence.read'}}),/differ/);
});

