import {EngineError} from './index.mjs';
import {ConsentLedger} from './consent-ledger.mjs';
import {assertVerifiedIdentity,authorizeRole} from './identity.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$/;
const bounded=(value,label)=>{ensure(typeof value==='string'&&ID.test(value),'INVALID_GATEWAY_POLICY',`${label} is required`);return value;};
const deny=(reason,details={})=>Object.freeze({allow:false,reason,...details,syntheticOnly:true});
const compiledPolicies=new WeakSet();

export function createGatewayPolicy({version,rules}){
 bounded(version,'Policy version');
 ensure(Array.isArray(rules)&&rules.length>0&&rules.length<=128,'INVALID_GATEWAY_POLICY','At least one bounded gateway rule is required');
 const byAction=Object.create(null);
 for(const candidate of rules){
  const action=bounded(candidate?.action,'Action');
  ensure(!Object.hasOwn(byAction,action),'INVALID_GATEWAY_POLICY','Gateway actions must be unique');
  const permission=bounded(candidate.permission,'Permission');
  const consentScope=candidate.consentScope==null?null:bounded(candidate.consentScope,'Consent scope');
  const requiresMfa=candidate.requiresMfa===true;
  ensure(candidate.requiresMfa==null||typeof candidate.requiresMfa==='boolean','INVALID_GATEWAY_POLICY','MFA requirement must be boolean');
  byAction[action]=Object.freeze({action,permission,consentScope,requiresMfa});
 }
 const policy=Object.freeze({version,rules:Object.freeze(byAction)});
 compiledPolicies.add(policy);
 return policy;
}

export class PolicyGateway {
 #policy;
 #rolePolicy;
 constructor({policy,rolePolicy}){
  ensure(compiledPolicies.has(policy),'INVALID_GATEWAY_POLICY','Compiled gateway policy is required');
  ensure(rolePolicy?.roles&&Object.isFrozen(rolePolicy.roles),'INVALID_ROLE_POLICY','Compiled role policy is required');
  this.#policy=policy;this.#rolePolicy=rolePolicy;
 }

 decide({identity,action,resourceTenantId,assignments,consentLedger=null,consentId=null,now=Date.now()}){
  const common={policyVersion:this.#policy.version,action:typeof action==='string'?action:null};
  if(typeof action!=='string'||!Object.hasOwn(this.#policy.rules,action))return deny('NO_POLICY_RULE',common);
  if(!Number.isSafeInteger(now)||now<0)return deny('INVALID_REQUEST',common);
  try{assertVerifiedIdentity(identity);}catch{return deny('IDENTITY_UNVERIFIED',common);}
  const identified={...common,tenantId:identity.tenantId,subject:identity.subject};
  if(resourceTenantId!==identity.tenantId)return deny('TENANT_DENIED',identified);
  const rule=this.#policy.rules[action];
  let role;
  try{role=authorizeRole(identity,{assignments,policy:this.#rolePolicy,permission:rule.permission,now,mfa:rule.requiresMfa?{}:null});}
  catch(error){
   const reason=error?.code==='MFA_REQUIRED'?'MFA_REQUIRED':error?.code==='IDENTITY_EXPIRED'?'IDENTITY_EXPIRED':'ROLE_DENIED';
   return deny(reason,identified);
  }
  if(rule.consentScope!==null){
   if(!(consentLedger instanceof ConsentLedger)||typeof consentId!=='string')return deny('CONSENT_REQUIRED',identified);
   try{if(!ConsentLedger.prototype.permits.call(consentLedger,identity,{consentId,scope:rule.consentScope,now}))return deny('CONSENT_DENIED',identified);}
   catch{return deny('CONSENT_DENIED',identified);}
  }
  return Object.freeze({allow:true,reason:'POLICY_ALLOWED',...identified,permission:rule.permission,roles:role.roles,consentScope:rule.consentScope,syntheticOnly:true});
 }
}
