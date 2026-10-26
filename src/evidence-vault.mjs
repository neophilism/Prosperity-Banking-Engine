import {EngineError} from './index.mjs';
import {authorizeDataUse} from './data-classification.mjs';
import {assertVerifiedIdentity} from './identity.mjs';
import {PolicyGateway} from './policy-gateway.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$/;
const DIGEST=/^[a-f0-9]{64}$/;
const compiledContracts=new WeakSet();
const bounded=(value,label)=>{ensure(typeof value==='string'&&ID.test(value),'INVALID_EVIDENCE',`${label} is required`);return value;};
const activeIdentity=(identity,now)=>{assertVerifiedIdentity(identity);ensure(Number.isSafeInteger(now)&&now>=identity.authenticatedAt&&identity.expiresAt>now,'IDENTITY_EXPIRED','Active verified identity is required');};

export function createEvidenceVaultContract({version,actions}){
 bounded(version,'Vault version');
 ensure(actions&&Object.getPrototypeOf(actions)===Object.prototype,'INVALID_EVIDENCE_CONTRACT','Vault actions are required');
 const normalized=Object.freeze({read:bounded(actions.read,'Read action'),write:bounded(actions.write,'Write action')});
 ensure(normalized.read!==normalized.write,'INVALID_EVIDENCE_CONTRACT','Read and write actions must differ');
 const contract=Object.freeze({version,actions:normalized,storesRawEvidence:false,syntheticOnly:true});
 compiledContracts.add(contract);return contract;
}

export class TenantEvidenceVault {
 #contract;#gateway;#records=new Map();#requests=new Map();
 constructor({contract,gateway}){
  ensure(compiledContracts.has(contract),'INVALID_EVIDENCE_CONTRACT','Compiled evidence vault contract is required');
  ensure(gateway instanceof PolicyGateway,'INVALID_EVIDENCE_CONTRACT','Policy gateway is required');
  this.#contract=contract;this.#gateway=gateway;
 }

 #authorize(identity,action,{assignments,now}){
  activeIdentity(identity,now);
  const decision=PolicyGateway.prototype.decide.call(this.#gateway,{identity,action,resourceTenantId:identity.tenantId,assignments,now});
  ensure(decision?.allow===true&&decision.action===action&&decision.tenantId===identity.tenantId&&decision.subject===identity.subject,'EVIDENCE_DENIED','Exact policy authorization is required');
 }

 store(request){
  const {identity,requestId,evidenceId,category,contentDigest,keyReference,mediaType,sizeBytes,capturedAt,source,assignments,now=Date.now()}=request??{};
  this.#authorize(identity,this.#contract.actions.write,{assignments,now});
  for(const raw of ['content','plaintext','ciphertext','bytes','data'])ensure(!Object.hasOwn(request,raw),'RAW_EVIDENCE_DENIED','Raw evidence must remain outside the metadata vault');
  bounded(requestId,'Request ID');bounded(evidenceId,'Evidence ID');bounded(keyReference,'External key reference');bounded(mediaType,'Media type');bounded(source,'Evidence source');
  ensure(typeof contentDigest==='string'&&DIGEST.test(contentDigest),'INVALID_EVIDENCE','Lowercase SHA-256 content digest is required');
  ensure(Number.isSafeInteger(sizeBytes)&&sizeBytes>=1&&sizeBytes<=100_000_000,'INVALID_EVIDENCE','Evidence size must be between 1 and 100000000 bytes');
  ensure(Number.isSafeInteger(capturedAt)&&capturedAt>=0&&capturedAt<=now,'INVALID_EVIDENCE','Captured time must be a nonnegative time no later than now');
  const dataUse=authorizeDataUse({category,tenantId:identity.tenantId,operation:'write'});
  const requestKey=`${identity.tenantId}:${requestId}`,recordKey=`${identity.tenantId}:${evidenceId}`;
  const digest=JSON.stringify([identity.issuer,identity.subject,this.#contract.version,evidenceId,category,contentDigest,keyReference,mediaType,sizeBytes,capturedAt,source]);
  const replay=this.#requests.get(requestKey);if(replay){ensure(replay.digest===digest,'REPLAY_MISMATCH','Evidence request replay has different terms');return this.#records.get(replay.recordKey);}
  ensure(!this.#records.has(recordKey),'EVIDENCE_CONFLICT','Evidence ID already exists');
  const record=Object.freeze({evidenceId,tenantId:identity.tenantId,category,classification:dataUse.classification,contentDigest,keyReference,mediaType,sizeBytes,capturedAt,source,recordedAt:now,producer:Object.freeze({issuer:identity.issuer,subject:identity.subject}),vaultVersion:this.#contract.version,syntheticOnly:true});
  this.#records.set(recordKey,record);this.#requests.set(requestKey,{digest,recordKey});return record;
 }

 get({identity,evidenceId,assignments,now=Date.now()}){
  this.#authorize(identity,this.#contract.actions.read,{assignments,now});bounded(evidenceId,'Evidence ID');
  const record=this.#records.get(`${identity.tenantId}:${evidenceId}`);ensure(record,'EVIDENCE_NOT_FOUND','Evidence does not exist');return record;
 }

 list({identity,assignments,limit=100,now=Date.now()}){
  this.#authorize(identity,this.#contract.actions.read,{assignments,now});
  ensure(Number.isInteger(limit)&&limit>=1&&limit<=100,'INVALID_EVIDENCE','List limit must be between 1 and 100');
  return Object.freeze([...this.#records.values()].filter(record=>record.tenantId===identity.tenantId).slice(0,limit));
 }
}

