import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity} from '../src/identity.mjs';
import {createEventSchema,EventOutbox} from '../src/event-outbox.mjs';

const now=5_000_000;
const identityFor=async(tenantId='tenant_alpha',subject='worker-7')=>authenticateIdentity({credential:'valid',now},async()=>({verified:true,tenantId,issuer:'https://identity.example',subject,authenticatedAt:now-1_000,expiresAt:now+600_000,authenticationMethods:['workload']}));
const schema=createEventSchema({type:'account.snapshot.recorded',version:'v1',requiredFields:['accountId','balanceMinor']});
const command=(overrides={})=>({eventId:'event-1',aggregateId:'account-7',payload:{balanceMinor:1200,accountId:'account-7'},idempotencyKey:'request-1',occurredAt:now,now,...overrides});

test('enqueues a canonical immutable versioned event and replays exact requests',async()=>{
 const identity=await identityFor(),outbox=new EventOutbox();
 const first=outbox.enqueue(identity,schema,command({payload:{accountId:'account-7',balanceMinor:1200}}));
 const replay=outbox.enqueue(identity,schema,command({payload:{balanceMinor:1200,accountId:'account-7'}}));
 assert.strictEqual(replay,first);assert.equal(first.state,'PENDING');assert.equal(first.schemaVersion,'v1');assert.equal(Object.isFrozen(first.payload),true);
 assert.throws(()=>{first.payload.balanceMinor=0;},TypeError);
 assert.throws(()=>outbox.enqueue(identity,schema,command({payload:{accountId:'account-7',balanceMinor:1300}})),/different terms/);
});

test('schema validation fails closed for missing, non-JSON and forged schemas',async()=>{
 const identity=await identityFor(),outbox=new EventOutbox();
 assert.throws(()=>outbox.enqueue(identity,schema,command({payload:{accountId:'account-7'}})),/balanceMinor/);
 assert.throws(()=>outbox.enqueue(identity,schema,command({payload:{accountId:'account-7',balanceMinor:NaN}})),/finite/);
 assert.throws(()=>outbox.enqueue(identity,Object.freeze({...schema}),command()),/Compiled event/);
 assert.throws(()=>createEventSchema({type:'event',version:'v1',requiredFields:['id','id']}),/unique/);
});

test('claims tenant events with exact renewable lease versions and publishes once',async()=>{
 const identity=await identityFor(),outbox=new EventOutbox();outbox.enqueue(identity,schema,command());
 const first=outbox.claim(identity,{workerId:'publisher-a',now,leaseMs:100})[0];assert.equal(first.deliveryVersion,1);
 assert.deepEqual(outbox.claim(identity,{workerId:'publisher-b',now:now+50,leaseMs:100}),[]);
 const reclaimed=outbox.claim(identity,{workerId:'publisher-b',now:now+100,leaseMs:100})[0];assert.equal(reclaimed.deliveryVersion,2);
 assert.throws(()=>outbox.complete(identity,{eventId:'event-1',workerId:'publisher-a',leaseVersion:1,now:now+101}),/Exact active/);
 const published=outbox.complete(identity,{eventId:'event-1',workerId:'publisher-b',leaseVersion:2,now:now+101});assert.equal(published.state,'PUBLISHED');assert.equal(published.publishedAt,now+101);
 assert.deepEqual(outbox.claim(identity,{workerId:'publisher-c',now:now+500}),[]);
});

test('tenant isolation and verifier provenance protect event visibility and mutation',async()=>{
 const alpha=await identityFor(),beta=await identityFor('tenant_beta'),outbox=new EventOutbox();outbox.enqueue(alpha,schema,command());
 assert.deepEqual(outbox.list(beta,{now}),[]);assert.deepEqual(outbox.claim(beta,{workerId:'publisher',now}),[]);
 assert.throws(()=>outbox.list({...alpha},{now}),/Verified identity/);
 assert.throws(()=>outbox.complete(beta,{eventId:'event-1',workerId:'publisher',leaseVersion:1,now}),/does not exist/);
});

test('event and idempotency keys are tenant scoped while duplicate event IDs fail',async()=>{
 const alpha=await identityFor(),beta=await identityFor('tenant_beta'),outbox=new EventOutbox();outbox.enqueue(alpha,schema,command());outbox.enqueue(beta,schema,command());
 assert.equal(outbox.list(alpha,{now}).length,1);assert.equal(outbox.list(beta,{now}).length,1);
 assert.throws(()=>outbox.enqueue(alpha,schema,command({idempotencyKey:'request-2'})),/Event ID already/);
});

test('expired identities cannot enqueue, claim, complete or list events',async()=>{
 const identity=await identityFor(),outbox=new EventOutbox();outbox.enqueue(identity,schema,command());
 const expiredAt=now+600_000;
 assert.throws(()=>outbox.enqueue(identity,schema,command({eventId:'event-2',idempotencyKey:'request-2',occurredAt:expiredAt,now:expiredAt})),/Active verified/);
 assert.throws(()=>outbox.claim(identity,{workerId:'publisher',now:expiredAt}),/Active verified/);
 assert.throws(()=>outbox.complete(identity,{eventId:'event-1',workerId:'publisher',leaseVersion:1,now:expiredAt}),/Active verified/);
 assert.throws(()=>outbox.list(identity,{now:expiredAt}),/Active verified/);
});
