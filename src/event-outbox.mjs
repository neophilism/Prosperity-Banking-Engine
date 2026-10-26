import {EngineError} from './index.mjs';
import {assertVerifiedIdentity} from './identity.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$/;
const bounded=(value,label)=>{ensure(typeof value==='string'&&ID.test(value),'INVALID_EVENT',`${label} is required`);return value;};
const compiledSchemas=new WeakSet();
const activeIdentity=(identity,now)=>{assertVerifiedIdentity(identity);ensure(Number.isSafeInteger(now)&&now>=identity.authenticatedAt&&identity.expiresAt>now,'IDENTITY_EXPIRED','Active verified identity is required');};

function normalizeJson(value,depth=0){
 ensure(depth<=8,'INVALID_EVENT','Event payload nesting is too deep');
 if(value===null||typeof value==='string'||typeof value==='boolean')return value;
 if(typeof value==='number'){ensure(Number.isFinite(value),'INVALID_EVENT','Event payload numbers must be finite');return value;}
 if(Array.isArray(value)){ensure(value.length<=128,'INVALID_EVENT','Event payload arrays are too large');return value.map(item=>normalizeJson(item,depth+1));}
 ensure(value&&typeof value==='object'&&(Object.getPrototypeOf(value)===Object.prototype||Object.getPrototypeOf(value)===null),'INVALID_EVENT','Event payload must contain JSON values only');
 const keys=Object.keys(value).sort();ensure(keys.length<=128,'INVALID_EVENT','Event payload objects are too large');
 const result=Object.create(null);for(const key of keys){bounded(key,'Payload field');ensure(value[key]!==undefined,'INVALID_EVENT','Undefined event payload values are not allowed');result[key]=normalizeJson(value[key],depth+1);}return result;
}
function freezeJson(value){if(value&&typeof value==='object'){for(const child of Object.values(value))freezeJson(child);Object.freeze(value);}return value;}

export function createEventSchema({type,version,requiredFields=[]}){
 bounded(type,'Event type');bounded(version,'Schema version');
 ensure(Array.isArray(requiredFields)&&requiredFields.length<=64,'INVALID_EVENT_SCHEMA','Required fields must be a bounded array');
 const fields=[...new Set(requiredFields.map(field=>bounded(field,'Required field')))];
 ensure(fields.length===requiredFields.length,'INVALID_EVENT_SCHEMA','Required fields must be unique');
 const schema=Object.freeze({type,version,requiredFields:Object.freeze(fields.sort())});compiledSchemas.add(schema);return schema;
}

export class EventOutbox {
 #events=new Map();
 #requests=new Map();

 enqueue(identity,schema,{eventId,aggregateId,payload,idempotencyKey,occurredAt=Date.now(),now=Date.now()}){
  activeIdentity(identity,now);ensure(compiledSchemas.has(schema),'INVALID_EVENT_SCHEMA','Compiled event schema is required');
  bounded(eventId,'Event ID');bounded(aggregateId,'Aggregate ID');bounded(idempotencyKey,'Idempotency key');
  ensure(Number.isSafeInteger(occurredAt)&&occurredAt>=0&&occurredAt<=now,'INVALID_EVENT','Event time must be a nonnegative time no later than now');
  const normalized=normalizeJson(payload);for(const field of schema.requiredFields)ensure(Object.hasOwn(normalized,field),'INVALID_EVENT',`Required payload field ${field} is missing`);
  const requestKey=`${identity.tenantId}:${idempotencyKey}`,eventKey=`${identity.tenantId}:${eventId}`;
  const digest=JSON.stringify([identity.issuer,identity.subject,schema.type,schema.version,eventId,aggregateId,occurredAt,normalized]);
  const replay=this.#requests.get(requestKey);if(replay){ensure(replay.digest===digest,'REPLAY_MISMATCH','Outbox request replay has different terms');return this.#events.get(replay.eventKey);}
  ensure(!this.#events.has(eventKey),'EVENT_CONFLICT','Event ID already exists');
  const result=Object.freeze({eventId,tenantId:identity.tenantId,type:schema.type,schemaVersion:schema.version,aggregateId,occurredAt,payload:freezeJson(normalized),producer:Object.freeze({issuer:identity.issuer,subject:identity.subject}),state:'PENDING',deliveryVersion:0,lease:null,publishedAt:null,syntheticOnly:true});
  this.#events.set(eventKey,result);this.#requests.set(requestKey,{digest,eventKey});return result;
 }

 claim(identity,{workerId,limit=10,leaseMs=30_000,now=Date.now()}){
  activeIdentity(identity,now);bounded(workerId,'Worker ID');
  ensure(Number.isInteger(limit)&&limit>=1&&limit<=100&&Number.isSafeInteger(leaseMs)&&leaseMs>=1&&leaseMs<=300_000&&Number.isSafeInteger(now)&&now>=0,'INVALID_LEASE','Outbox lease parameters are invalid');
  const claimed=[];
  for(const [key,event] of this.#events){
   if(claimed.length===limit)break;
   if(event.tenantId!==identity.tenantId||event.state==='PUBLISHED'||(event.state==='CLAIMED'&&event.lease.expiresAt>now))continue;
   const next=Object.freeze({...event,state:'CLAIMED',deliveryVersion:event.deliveryVersion+1,lease:Object.freeze({workerId,version:event.deliveryVersion+1,expiresAt:now+leaseMs})});
   this.#events.set(key,next);claimed.push(next);
  }
  return Object.freeze(claimed);
 }

 complete(identity,{eventId,workerId,leaseVersion,now=Date.now()}){
  activeIdentity(identity,now);bounded(eventId,'Event ID');bounded(workerId,'Worker ID');
  ensure(Number.isSafeInteger(leaseVersion)&&leaseVersion>=1&&Number.isSafeInteger(now)&&now>=0,'INVALID_LEASE','Outbox completion parameters are invalid');
  const key=`${identity.tenantId}:${eventId}`,event=this.#events.get(key);ensure(event,'EVENT_NOT_FOUND','Outbox event does not exist');
  ensure(event.state==='CLAIMED'&&event.lease.workerId===workerId&&event.lease.version===leaseVersion,'LEASE_DENIED','Exact active outbox lease is required');
  ensure(now<event.lease.expiresAt,'LEASE_EXPIRED','Outbox lease expired');
  const published=Object.freeze({...event,state:'PUBLISHED',lease:null,publishedAt:now});this.#events.set(key,published);return published;
 }

 list(identity,{now=Date.now()}={}){activeIdentity(identity,now);return Object.freeze([...this.#events.values()].filter(event=>event.tenantId===identity.tenantId));}
}
