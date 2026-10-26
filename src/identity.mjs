import {EngineError} from './index.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const IDENTIFIER=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,255}$/;
const TENANT=/^tenant_[a-z0-9_-]+$/;
const verifiedIdentities=new WeakSet();

function boundedIdentifier(value,label){
 ensure(typeof value==='string'&&IDENTIFIER.test(value),'INVALID_IDENTITY',`${label} is required`);
 return value;
}

export function assertVerifiedIdentity(identity){
 ensure(verifiedIdentities.has(identity),'IDENTITY_UNVERIFIED','Verified identity is required');
 return identity;
}

/** Accept identity claims only after a configured adapter has verified their authenticity. */
export async function authenticateIdentity({credential,now=Date.now()},verifyCredential){
 ensure(typeof verifyCredential==='function','IDENTITY_VERIFIER_REQUIRED','A credential verifier is required');
 ensure(typeof credential==='string'&&credential.length>0&&credential.length<=8192,'INVALID_CREDENTIAL','A bounded credential is required');
 ensure(Number.isSafeInteger(now)&&now>=0,'INVALID_TIME','Current time must be a nonnegative integer');
 const claims=await verifyCredential(credential);
 ensure(claims?.verified===true,'IDENTITY_UNVERIFIED','Credential verification failed');
 const tenantId=claims.tenantId;
 ensure(typeof tenantId==='string'&&TENANT.test(tenantId),'INVALID_TENANT','Verified tenant claim is required');
 const issuer=boundedIdentifier(claims.issuer,'Verified issuer');
 const subject=boundedIdentifier(claims.subject,'Verified subject');
 ensure(Number.isSafeInteger(claims.authenticatedAt)&&claims.authenticatedAt>=0&&claims.authenticatedAt<=now,'INVALID_AUTH_TIME','Verified authentication time is invalid');
 ensure(Number.isSafeInteger(claims.expiresAt)&&claims.expiresAt>now,'IDENTITY_EXPIRED','Verified identity is expired');
 ensure(Array.isArray(claims.authenticationMethods)&&claims.authenticationMethods.length>0&&claims.authenticationMethods.length<=8,'INVALID_AUTH_METHODS','Verified authentication methods are required');
 const authenticationMethods=[...new Set(claims.authenticationMethods.map(method=>boundedIdentifier(method,'Authentication method')))];
 const identity=Object.freeze({tenantId,issuer,subject,authenticatedAt:claims.authenticatedAt,expiresAt:claims.expiresAt,authenticationMethods:Object.freeze(authenticationMethods),verified:true});
 verifiedIdentities.add(identity);
 return identity;
}

export function createRolePolicy(definitions){
 ensure(Array.isArray(definitions)&&definitions.length>0&&definitions.length<=64,'INVALID_ROLE_POLICY','At least one bounded role is required');
 const roles=Object.create(null);
 for(const definition of definitions){
  const name=boundedIdentifier(definition?.name,'Role name');
  ensure(!Object.hasOwn(roles,name),'INVALID_ROLE_POLICY','Role names must be unique');
  ensure(Array.isArray(definition.permissions)&&definition.permissions.length>0&&definition.permissions.length<=64,'INVALID_ROLE_POLICY','Role permissions are required');
  const permissions=[...new Set(definition.permissions.map(permission=>boundedIdentifier(permission,'Permission')))];
  roles[name]=Object.freeze({name,permissions:Object.freeze(permissions)});
 }
 return Object.freeze({roles:Object.freeze(roles)});
}

function matchingAssignments(identity,assignments,policy,now){
 assertVerifiedIdentity(identity);
 ensure(TENANT.test(identity.tenantId??''),'IDENTITY_UNVERIFIED','Verified identity is required');
 ensure(Array.isArray(assignments),'INVALID_ASSIGNMENTS','Role assignments are required');
 return assignments.filter(assignment=>{
  ensure(assignment&&typeof assignment==='object','INVALID_ASSIGNMENTS','Role assignment is invalid');
  if(assignment.tenantId!==identity.tenantId||assignment.issuer!==identity.issuer||assignment.subject!==identity.subject)return false;
  ensure(Object.hasOwn(policy.roles,assignment.role),'UNKNOWN_ROLE','Role assignment references an unknown role');
  ensure(Number.isSafeInteger(assignment.validFrom)&&Number.isSafeInteger(assignment.validUntil)&&assignment.validFrom>=0&&assignment.validUntil>assignment.validFrom,'INVALID_ASSIGNMENTS','Role assignment validity is invalid');
  return assignment.revoked!==true&&assignment.validFrom<=now&&now<assignment.validUntil;
 });
}

export function requireFreshMfa(identity,{now=Date.now(),maxAgeMs=300000,minFactors=2}={}){
 assertVerifiedIdentity(identity);
 ensure(Number.isSafeInteger(now)&&now>=0&&Number.isSafeInteger(maxAgeMs)&&maxAgeMs>=1&&maxAgeMs<=3600000,'INVALID_MFA_POLICY','MFA time policy is invalid');
 ensure(Number.isInteger(minFactors)&&minFactors>=2&&minFactors<=4,'INVALID_MFA_POLICY','MFA factor count is invalid');
 ensure(identity.expiresAt>now,'IDENTITY_EXPIRED','Verified identity is expired');
 ensure(identity.authenticatedAt<=now&&now-identity.authenticatedAt<=maxAgeMs,'MFA_REQUIRED','Fresh authentication is required');
 ensure(new Set(identity.authenticationMethods).size>=minFactors,'MFA_REQUIRED','Multiple verified authentication methods are required');
 return Object.freeze({satisfied:true,authenticatedAt:identity.authenticatedAt,factorCount:new Set(identity.authenticationMethods).size});
}

export function authorizeRole(identity,{assignments,policy,permission,now=Date.now(),mfa=null}){
 boundedIdentifier(permission,'Permission');
 ensure(policy?.roles&&Object.isFrozen(policy.roles),'INVALID_ROLE_POLICY','Role policy is required');
 ensure(Number.isSafeInteger(now)&&now>=0,'INVALID_TIME','Current time must be a nonnegative integer');
 ensure(identity?.expiresAt>now,'IDENTITY_EXPIRED','Verified identity is expired');
 const active=matchingAssignments(identity,assignments,policy,now);
 const grantedRoles=active.filter(assignment=>policy.roles[assignment.role].permissions.includes(permission)).map(assignment=>assignment.role);
 ensure(grantedRoles.length>0,'ROLE_DENIED','No active tenant-bound role grants this permission');
 const mfaEvidence=mfa?requireFreshMfa(identity,{now,...mfa}):null;
 return Object.freeze({allow:true,tenantId:identity.tenantId,subject:identity.subject,permission,roles:Object.freeze([...new Set(grantedRoles)]),mfa:mfaEvidence,syntheticOnly:true});
}
