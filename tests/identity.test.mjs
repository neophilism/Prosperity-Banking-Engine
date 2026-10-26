import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity,authorizeRole,createRolePolicy,requireFreshMfa} from '../src/identity.mjs';

const now=2_000_000;
const verifiedClaims={verified:true,tenantId:'tenant_alpha',issuer:'https://identity.example',subject:'user-7',authenticatedAt:now-30_000,expiresAt:now+600_000,authenticationMethods:['password','webauthn']};
const verify=async credential=>credential==='valid'?verifiedClaims:{verified:false};
const policy=createRolePolicy([{name:'reader',permissions:['accounts:read']},{name:'operator',permissions:['accounts:read','payments:prepare']}]);
const assignment=(overrides={})=>({tenantId:'tenant_alpha',issuer:'https://identity.example',subject:'user-7',role:'operator',validFrom:now-60_000,validUntil:now+60_000,revoked:false,...overrides});

test('identity requires an external verifier and rejects forged or expired claims',async()=>{
 await assert.rejects(()=>authenticateIdentity({credential:'valid',now}),/verifier/i);
 await assert.rejects(()=>authenticateIdentity({credential:'forged',now},verify),/verification failed/);
 await assert.rejects(()=>authenticateIdentity({credential:'valid',now},async()=>({...verifiedClaims,expiresAt:now})),/expired/);
 await assert.rejects(()=>authenticateIdentity({credential:'valid',now},async()=>({...verifiedClaims,tenantId:'caller-choice'})),/tenant/);
});

test('verified identity is immutable and preserves only bounded authorization claims',async()=>{
 const identity=await authenticateIdentity({credential:'valid',now},verify);
 assert.equal(identity.tenantId,'tenant_alpha');
 assert.deepEqual(identity.authenticationMethods,['password','webauthn']);
 assert.equal(Object.isFrozen(identity),true);
 assert.throws(()=>{identity.subject='other';},TypeError);
});

test('roles are tenant and subject bound, active, known and deny by default',async()=>{
 const identity=await authenticateIdentity({credential:'valid',now},verify);
 assert.equal(authorizeRole(identity,{assignments:[assignment()],policy,permission:'payments:prepare',now}).allow,true);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({tenantId:'tenant_beta'})],policy,permission:'payments:prepare',now}),/No active/);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({subject:'user-8'})],policy,permission:'payments:prepare',now}),/No active/);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({revoked:true})],policy,permission:'payments:prepare',now}),/No active/);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({validUntil:now})],policy,permission:'payments:prepare',now}),/No active/);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({role:'invented'})],policy,permission:'payments:prepare',now}),/unknown role/i);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment({role:'reader'})],policy,permission:'payments:prepare',now}),/No active/);
});

test('sensitive authorization requires fresh evidence from multiple verified methods',async()=>{
 const identity=await authenticateIdentity({credential:'valid',now},verify);
 const allowed=authorizeRole(identity,{assignments:[assignment()],policy,permission:'payments:prepare',now,mfa:{maxAgeMs:60_000,minFactors:2}});
 assert.equal(allowed.mfa.satisfied,true);assert.equal(allowed.mfa.factorCount,2);
 assert.throws(()=>requireFreshMfa({...identity,authenticationMethods:['password']},{now,maxAgeMs:60_000}),/Multiple/);
 assert.throws(()=>requireFreshMfa({...identity,authenticatedAt:now-60_001},{now,maxAgeMs:60_000}),/Fresh/);
 assert.throws(()=>authorizeRole(identity,{assignments:[assignment()],policy,permission:'payments:prepare',now,mfa:{minFactors:1}}),/factor count/);
});

test('role policy rejects duplicate, empty and malformed definitions',()=>{
 assert.throws(()=>createRolePolicy([]),/role/i);
 assert.throws(()=>createRolePolicy([{name:'reader',permissions:['read']},{name:'reader',permissions:['write']}]),/unique/);
 assert.throws(()=>createRolePolicy([{name:'reader',permissions:[]}]),/permissions/);
 assert.throws(()=>{policy.roles.admin={name:'admin',permissions:['*']};},TypeError);
});
