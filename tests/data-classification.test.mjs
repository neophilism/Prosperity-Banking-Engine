import test from 'node:test';
import assert from 'node:assert/strict';
import {DATA_CLASSES,DATA_CATEGORIES,authorizeDataUse,classifyData} from '../src/data-classification.mjs';

test('classification catalog covers bank-sensitive assets explicitly',()=>{
 assert.equal(classifyData('public_content').classification,DATA_CLASSES.PUBLIC);
 for(const category of ['customer_identity','customer_financial_data','customer_document','credential_or_auth_factor','consent_or_audit_evidence','embedding_or_derived_profile']){
  assert.equal(classifyData(category).classification,DATA_CLASSES.RESTRICTED);
  assert.equal(DATA_CATEGORIES[category].tenantScoped,true);
 }
 assert.throws(()=>classifyData('miscellaneous'),error=>error.code==='UNKNOWN_DATA_CATEGORY');
});

test('non-public use requires a validated tenant and rejects cross-tenant movement',()=>{
 assert.throws(()=>authorizeDataUse({category:'tenant_configuration',operation:'read'}),error=>error.code==='TENANT_REQUIRED');
 const decision=authorizeDataUse({category:'tenant_configuration',tenantId:'tenant_alpha',operation:'read'});
 assert.deepEqual(decision,{allow:true,category:'tenant_configuration',classification:'CONFIDENTIAL',tenantId:'tenant_alpha',operation:'read',destination:'tenant_application'});
 assert.throws(()=>authorizeDataUse({category:'operational_metadata',tenantId:'tenant_alpha',operation:'write',destination:'cross_tenant'}),error=>error.code==='DATA_USE_DENIED');
});

test('restricted values cannot enter logs, model contexts, or public output',()=>{
 for(const operation of ['log','model_input','publish']){
  assert.throws(()=>authorizeDataUse({category:'customer_financial_data',tenantId:'tenant_alpha',operation}),error=>error.code==='DATA_USE_DENIED');
 }
 assert.equal(authorizeDataUse({category:'public_content',operation:'publish',destination:'public'}).allow,true);
 assert.equal(authorizeDataUse({category:'synthetic_test_data',operation:'log'}).allow,true);
});

test('model use is explicit and does not imply a banking authorization',()=>{
 const decision=authorizeDataUse({category:'model_prompt_or_output',tenantId:'tenant_alpha',operation:'model_input'});
 assert.equal(decision.classification,DATA_CLASSES.CONFIDENTIAL);
 assert.equal(decision.allow,true);
 assert.equal(decision.destination,'approved_model');
 assert.equal('paymentApproved' in decision,false);
 assert.throws(()=>authorizeDataUse({category:'staff_notes',tenantId:'tenant_alpha',operation:'model_input'}),error=>error.code==='DATA_USE_DENIED');
 assert.throws(()=>authorizeDataUse({category:'public_content',operation:'erase'}),error=>error.code==='INVALID_DATA_OPERATION');
});
