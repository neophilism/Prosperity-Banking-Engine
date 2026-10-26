import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticateIdentity} from '../src/identity.mjs';
import {createBankAdapterContract,FakeBankLedger} from '../src/bank-adapter.mjs';

const now=7_000_000;
const identityFor=(tenantId='tenant_alpha',subject='operator')=>authenticateIdentity({credential:'valid',now},async()=>({verified:true,tenantId,issuer:'https://identity.example',subject,authenticatedAt:now-1_000,expiresAt:now+600_000,authenticationMethods:['workload']}));
const contract=createBankAdapterContract({name:'fake-ledger',version:'v1',capabilities:['accounts.read','transactions.read','payments.simulate']});
const ledger=()=>new FakeBankLedger(contract,{accounts:[{tenantId:'tenant_alpha',accountId:'checking-1',currency:'USD',balanceMinor:10_000},{tenantId:'tenant_beta',accountId:'checking-1',currency:'USD',balanceMinor:20_000}],transactions:[{tenantId:'tenant_alpha',accountId:'checking-1',transactionId:'opening-1',amountMinor:10_000,currency:'USD',description:'Synthetic opening balance'}]});
const authorized=tenantId=>Object.freeze({allow:true,tenantId,syntheticOnly:true});

test('contract permits only bounded synthetic capabilities',()=>{
 assert.equal(contract.mode,'SYNTHETIC_ONLY');assert.equal(contract.canSettle,false);assert.equal(Object.isFrozen(contract.capabilities),true);
 assert.throws(()=>createBankAdapterContract({name:'live',version:'v1',capabilities:['payments.settle']}),/supported/);
 assert.throws(()=>new FakeBankLedger({...contract}),/Compiled/);
});

test('account and transaction reads are tenant isolated and immutable',async()=>{
 const alpha=await identityFor(),beta=await identityFor('tenant_beta'),fake=ledger();
 assert.equal(fake.accounts(alpha,{now})[0].balanceMinor,10_000);assert.equal(fake.accounts(beta,{now})[0].balanceMinor,20_000);
 assert.equal(fake.transactions(alpha,{accountId:'checking-1',now}).length,1);assert.deepEqual(fake.transactions(beta,{accountId:'checking-1',now}),[]);
 assert.throws(()=>fake.accounts({...alpha},{now}),/Verified identity/);
});

test('payments are simulated, non-settling and exactly idempotent',async()=>{
 const alpha=await identityFor(),fake=ledger(),command={requestId:'pay-1',accountId:'checking-1',amountMinor:1250,currency:'USD',destinationToken:'vendor-token',authorized:authorized('tenant_alpha'),now};
 const first=fake.simulatePayment(alpha,command),replay=fake.simulatePayment(alpha,command);
 assert.strictEqual(replay,first);assert.deepEqual(first,{requestId:'pay-1',transactionId:'sim-pay-1',state:'SIMULATED',settled:false,tenantId:'tenant_alpha',syntheticOnly:true});
 assert.equal(fake.accounts(alpha,{now})[0].balanceMinor,8750);assert.equal(fake.transactions(alpha,{accountId:'checking-1',now}).length,2);
 assert.throws(()=>fake.simulatePayment(alpha,{...command,amountMinor:1300}),/different terms/);
});

test('payment simulation fails closed for tenant, authorization, currency and funds',async()=>{
 const alpha=await identityFor(),beta=await identityFor('tenant_beta'),fake=ledger(),base={requestId:'pay-2',accountId:'checking-1',amountMinor:100,currency:'USD',destinationToken:'vendor-token',now};
 assert.throws(()=>fake.simulatePayment(alpha,{...base,authorized:authorized('tenant_beta')}),/authorization/);
 assert.throws(()=>fake.simulatePayment(alpha,{...base,currency:'EUR',authorized:authorized('tenant_alpha')}),/currency/i);
 assert.throws(()=>fake.simulatePayment(alpha,{...base,amountMinor:10_001,authorized:authorized('tenant_alpha')}),/insufficient/);
 assert.throws(()=>fake.simulatePayment(beta,{...base,authorized:authorized('tenant_alpha')}),/authorization/);
});

test('transaction conflicts fail before changing synthetic balances',async()=>{
 const alpha=await identityFor(),fake=new FakeBankLedger(contract,{accounts:[{tenantId:'tenant_alpha',accountId:'checking-1',currency:'USD',balanceMinor:1000}],transactions:[{tenantId:'tenant_alpha',accountId:'checking-1',transactionId:'sim-pay-3',amountMinor:-1,currency:'USD',description:'Reserved synthetic transaction'}]});
 assert.throws(()=>fake.simulatePayment(alpha,{requestId:'pay-3',accountId:'checking-1',amountMinor:100,currency:'USD',destinationToken:'vendor-token',authorized:authorized('tenant_alpha'),now}),/already exists/);
 assert.equal(fake.accounts(alpha,{now})[0].balanceMinor,1000);
});

test('expired identities and undeclared capabilities cannot use the adapter',async()=>{
 const alpha=await identityFor(),readOnly=createBankAdapterContract({name:'read-only',version:'v1',capabilities:['accounts.read']}),fake=new FakeBankLedger(readOnly,{accounts:[{tenantId:'tenant_alpha',accountId:'checking-1',currency:'USD',balanceMinor:100}]});
 assert.throws(()=>fake.accounts(alpha,{now:alpha.expiresAt}),/Active verified/);
 assert.throws(()=>fake.transactions(alpha,{accountId:'checking-1',now}),/does not provide/);
 assert.throws(()=>fake.simulatePayment(alpha,{requestId:'x',accountId:'checking-1',amountMinor:1,currency:'USD',destinationToken:'x',authorized:authorized('tenant_alpha'),now}),/does not provide/);
});
