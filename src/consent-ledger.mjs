import {EngineError} from './index.mjs';
import {assertVerifiedIdentity} from './identity.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$/;
const bounded=(value,label)=>{ensure(typeof value==='string'&&ID.test(value),'INVALID_CONSENT',`${label} is required`);return value;};

function normalizeScopes(scopes){
 ensure(Array.isArray(scopes)&&scopes.length>0&&scopes.length<=32,'INVALID_CONSENT','At least one bounded scope is required');
 const normalized=[...new Set(scopes.map(scope=>bounded(scope,'Consent scope')))];
 return Object.freeze(normalized.sort((a,b)=>a.localeCompare(b)));
}

export class ConsentLedger {
 #events=[];
 #current=new Map();
 #requests=new Map();

 grant(identity,{consentId,scopes,purpose,policyVersion,expiresAt,requestId,now=Date.now()}){
  assertVerifiedIdentity(identity);
  bounded(consentId,'Consent ID');bounded(purpose,'Consent purpose');bounded(policyVersion,'Policy version');bounded(requestId,'Request ID');
  ensure(Number.isSafeInteger(now)&&now>=0&&Number.isSafeInteger(expiresAt)&&expiresAt>now,'INVALID_CONSENT','Consent expiry must be in the future');
  const normalizedScopes=normalizeScopes(scopes),key=`${identity.tenantId}:${consentId}`,requestKey=`${identity.tenantId}:${requestId}`;
  const digest=JSON.stringify(['GRANTED',consentId,identity.issuer,identity.subject,normalizedScopes,purpose,policyVersion,expiresAt]);
  const replay=this.#requests.get(requestKey);
  if(replay){ensure(replay.digest===digest,'REPLAY_MISMATCH','Consent request replay has different terms');return replay.result;}
  ensure(!this.#current.has(key),'CONSENT_CONFLICT','Consent ID already exists');
  const result=this.#append({type:'GRANTED',tenantId:identity.tenantId,consentId,subjectIssuer:identity.issuer,subject:identity.subject,scopes:normalizedScopes,purpose,policyVersion,expiresAt,occurredAt:now,version:1,requestId});
  this.#current.set(key,result);this.#requests.set(requestKey,{digest,result});return result;
 }

 revoke(identity,{consentId,expectedVersion,reason,requestId,now=Date.now()}){
  assertVerifiedIdentity(identity);
  bounded(consentId,'Consent ID');bounded(reason,'Revocation reason');bounded(requestId,'Request ID');
  ensure(Number.isSafeInteger(now)&&now>=0,'INVALID_TIME','Current time must be a nonnegative integer');
  const key=`${identity.tenantId}:${consentId}`,requestKey=`${identity.tenantId}:${requestId}`,current=this.#current.get(key);
  ensure(current,'CONSENT_NOT_FOUND','Consent does not exist');
  ensure(current.subjectIssuer===identity.issuer&&current.subject===identity.subject,'CONSENT_DENIED','Only the verified consent subject may revoke');
  const digest=JSON.stringify(['REVOKED',consentId,expectedVersion,reason]);
  const replay=this.#requests.get(requestKey);
  if(replay){ensure(replay.digest===digest,'REPLAY_MISMATCH','Consent request replay has different terms');return replay.result;}
  ensure(current.type==='GRANTED','CONSENT_REVOKED','Consent is already revoked');
  ensure(Number.isSafeInteger(expectedVersion)&&expectedVersion===current.version,'STALE_CONSENT','Consent version changed');
  const result=this.#append({...current,type:'REVOKED',occurredAt:now,version:current.version+1,requestId,reason});
  this.#current.set(key,result);this.#requests.set(requestKey,{digest,result});return result;
 }

 permits(identity,{consentId,scope,now=Date.now()}){
  assertVerifiedIdentity(identity);bounded(consentId,'Consent ID');bounded(scope,'Consent scope');
  ensure(Number.isSafeInteger(now)&&now>=0,'INVALID_TIME','Current time must be a nonnegative integer');
  const current=this.#current.get(`${identity.tenantId}:${consentId}`);
  return !!current&&current.type==='GRANTED'&&current.subjectIssuer===identity.issuer&&current.subject===identity.subject&&current.expiresAt>now&&current.scopes.includes(scope);
 }

 history(identity,consentId){
  assertVerifiedIdentity(identity);bounded(consentId,'Consent ID');
  return Object.freeze(this.#events.filter(event=>event.tenantId===identity.tenantId&&event.consentId===consentId&&event.subjectIssuer===identity.issuer&&event.subject===identity.subject));
 }

 #append(event){const frozen=Object.freeze({...event,sequence:this.#events.length+1});this.#events.push(frozen);return frozen;}
}
