import {EngineError} from './index.mjs';
import {assertVerifiedIdentity} from './identity.mjs';

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,127}$/;
const TENANT=/^tenant_[a-z0-9_-]+$/;
const CURRENCY=/^[A-Z]{3}$/;
const SUPPORTED=new Set(['accounts.read','transactions.read','payments.simulate']);
const compiledContracts=new WeakSet();
const bounded=(value,label)=>{ensure(typeof value==='string'&&ID.test(value),'INVALID_ADAPTER',`${label} is required`);return value;};
const boundedText=(value,label)=>{ensure(typeof value==='string'&&value.trim()===value&&value.length>0&&value.length<=256&&!/[\u0000-\u001f\u007f]/.test(value),'INVALID_ADAPTER',`${label} is required`);return value;};
const money=(value,label)=>{ensure(Number.isSafeInteger(value), 'INVALID_ADAPTER',`${label} must use integer minor units`);return value;};
const activeIdentity=(identity,now)=>{assertVerifiedIdentity(identity);ensure(Number.isSafeInteger(now)&&now>=identity.authenticatedAt&&identity.expiresAt>now,'IDENTITY_EXPIRED','Active verified identity is required');};
const cloneAccount=account=>Object.freeze({...account});
const cloneTransaction=transaction=>Object.freeze({...transaction});

export function createBankAdapterContract({name,version,capabilities}){
 bounded(name,'Adapter name');bounded(version,'Adapter version');
 ensure(Array.isArray(capabilities)&&capabilities.length>0&&capabilities.length<=SUPPORTED.size,'INVALID_ADAPTER','Adapter capabilities are required');
 const unique=[...new Set(capabilities)];
 ensure(unique.length===capabilities.length&&unique.every(capability=>SUPPORTED.has(capability)),'INVALID_ADAPTER','Adapter capabilities must be unique and supported');
 const contract=Object.freeze({name,version,capabilities:Object.freeze(unique.sort()),mode:'SYNTHETIC_ONLY',canSettle:false});
 compiledContracts.add(contract);return contract;
}

export class FakeBankLedger {
 #contract;
 #accounts=new Map();
 #transactions=new Map();
 #requests=new Map();

 constructor(contract,{accounts=[],transactions=[]}={}){
  ensure(compiledContracts.has(contract),'INVALID_ADAPTER','Compiled bank adapter contract is required');
  ensure(Array.isArray(accounts)&&Array.isArray(transactions),'INVALID_ADAPTER','Synthetic ledger fixtures must be arrays');
  this.#contract=contract;
  for(const candidate of accounts){
   const tenantId=candidate?.tenantId,accountId=bounded(candidate?.accountId,'Account ID'),currency=candidate?.currency;
   ensure(TENANT.test(tenantId??'')&&CURRENCY.test(currency??''),'INVALID_ADAPTER','Account tenant and currency are required');
   const key=`${tenantId}:${accountId}`;ensure(!this.#accounts.has(key),'INVALID_ADAPTER','Synthetic account IDs must be unique per tenant');
   this.#accounts.set(key,Object.freeze({tenantId,accountId,currency,balanceMinor:money(candidate.balanceMinor,'Account balance'),syntheticOnly:true}));
  }
  for(const candidate of transactions){
   const account=this.#accounts.get(`${candidate?.tenantId}:${candidate?.accountId}`);ensure(account,'INVALID_ADAPTER','Synthetic transaction account is required');
   const transactionId=bounded(candidate?.transactionId,'Transaction ID');ensure(CURRENCY.test(candidate?.currency??'')&&candidate.currency===account.currency,'INVALID_ADAPTER','Transaction currency must match the account');
   const key=`${candidate.tenantId}:${transactionId}`;ensure(!this.#transactions.has(key),'INVALID_ADAPTER','Synthetic transaction IDs must be unique per tenant');
   this.#transactions.set(key,Object.freeze({tenantId:candidate.tenantId,accountId:candidate.accountId,transactionId,amountMinor:money(candidate.amountMinor,'Transaction amount'),currency:candidate.currency,description:boundedText(candidate.description,'Transaction description'),state:'SIMULATED',settled:false,syntheticOnly:true}));
  }
 }

 #require(capability){ensure(this.#contract.capabilities.includes(capability),'ADAPTER_CAPABILITY_DENIED',`Adapter does not provide ${capability}`);}
 accounts(identity,{now=Date.now()}={}){activeIdentity(identity,now);this.#require('accounts.read');return Object.freeze([...this.#accounts.values()].filter(account=>account.tenantId===identity.tenantId).map(cloneAccount));}
 transactions(identity,{accountId,now=Date.now()}){activeIdentity(identity,now);this.#require('transactions.read');bounded(accountId,'Account ID');ensure(this.#accounts.has(`${identity.tenantId}:${accountId}`),'ACCOUNT_NOT_FOUND','Synthetic account does not exist');return Object.freeze([...this.#transactions.values()].filter(transaction=>transaction.tenantId===identity.tenantId&&transaction.accountId===accountId).map(cloneTransaction));}

 simulatePayment(identity,{requestId,accountId,amountMinor,currency,destinationToken,authorized,now=Date.now()}){
  activeIdentity(identity,now);this.#require('payments.simulate');bounded(requestId,'Request ID');bounded(accountId,'Account ID');bounded(destinationToken,'Destination token');
  ensure(authorized?.allow===true&&authorized.tenantId===identity.tenantId&&authorized.syntheticOnly===true,'PAYMENT_DENIED','Tenant-bound synthetic authorization is required');
  ensure(Number.isSafeInteger(amountMinor)&&amountMinor>0&&CURRENCY.test(currency??''),'INVALID_PAYMENT','Positive integer minor units and currency are required');
  const accountKey=`${identity.tenantId}:${accountId}`,account=this.#accounts.get(accountKey);ensure(account,'ACCOUNT_NOT_FOUND','Synthetic account does not exist');ensure(account.currency===currency,'CURRENCY_MISMATCH','Payment currency must match the account');
  const requestKey=`${identity.tenantId}:${requestId}`,digest=JSON.stringify([identity.issuer,identity.subject,accountId,amountMinor,currency,destinationToken]);
  const replay=this.#requests.get(requestKey);if(replay){ensure(replay.digest===digest,'REPLAY_MISMATCH','Payment replay has different terms');return replay.receipt;}
  ensure(account.balanceMinor>=amountMinor,'INSUFFICIENT_SYNTHETIC_FUNDS','Synthetic account has insufficient funds');
  const transactionId=`sim-${requestId}`,transactionKey=`${identity.tenantId}:${transactionId}`;bounded(transactionId,'Transaction ID');ensure(!this.#transactions.has(transactionKey),'TRANSACTION_CONFLICT','Synthetic transaction already exists');
  const transaction=Object.freeze({tenantId:identity.tenantId,accountId,transactionId,amountMinor:-amountMinor,currency,description:`Simulated payment to ${destinationToken}`,state:'SIMULATED',settled:false,syntheticOnly:true});
  this.#accounts.set(accountKey,Object.freeze({...account,balanceMinor:account.balanceMinor-amountMinor}));this.#transactions.set(transactionKey,transaction);
  const receipt=Object.freeze({requestId,transactionId,state:'SIMULATED',settled:false,tenantId:identity.tenantId,syntheticOnly:true});this.#requests.set(requestKey,{digest,receipt});return receipt;
 }
}
