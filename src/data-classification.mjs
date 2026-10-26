import {EngineError} from './index.mjs';

export const DATA_CLASSES=Object.freeze({
 PUBLIC:'PUBLIC',
 INTERNAL:'INTERNAL',
 CONFIDENTIAL:'CONFIDENTIAL',
 RESTRICTED:'RESTRICTED'
});

const categoryDefinitions={
 public_content:{classification:DATA_CLASSES.PUBLIC,tenantScoped:false,loggable:true,modelEligible:true},
 synthetic_test_data:{classification:DATA_CLASSES.INTERNAL,tenantScoped:false,loggable:true,modelEligible:true},
 operational_metadata:{classification:DATA_CLASSES.INTERNAL,tenantScoped:true,loggable:true,modelEligible:false},
 tenant_configuration:{classification:DATA_CLASSES.CONFIDENTIAL,tenantScoped:true,loggable:false,modelEligible:false},
 staff_notes:{classification:DATA_CLASSES.CONFIDENTIAL,tenantScoped:true,loggable:false,modelEligible:false},
 model_prompt_or_output:{classification:DATA_CLASSES.CONFIDENTIAL,tenantScoped:true,loggable:false,modelEligible:true},
 customer_identity:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false},
 customer_financial_data:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false},
 customer_document:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false},
 credential_or_auth_factor:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false},
 consent_or_audit_evidence:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false},
 embedding_or_derived_profile:{classification:DATA_CLASSES.RESTRICTED,tenantScoped:true,loggable:false,modelEligible:false}
};

export const DATA_CATEGORIES=Object.freeze(Object.fromEntries(
 Object.entries(categoryDefinitions).map(([name,value])=>[name,Object.freeze({...value})])
));

const ensure=(condition,code,message)=>{if(!condition)throw new EngineError(code,message);};

export function classifyData(category){
 ensure(typeof category==='string'&&Object.hasOwn(DATA_CATEGORIES,category),'UNKNOWN_DATA_CATEGORY','Explicit known data category required');
 return DATA_CATEGORIES[category];
}

export function authorizeDataUse({category,tenantId,operation,destination}){
 const definition=classifyData(category);
 const destinationByOperation={read:'tenant_application',write:'tenant_application',log:'application_log',model_input:'approved_model',publish:'public'};
 ensure(Object.hasOwn(destinationByOperation,operation),'INVALID_DATA_OPERATION','Known data operation required');
 const resolvedDestination=destination??destinationByOperation[operation];
 ensure(resolvedDestination===destinationByOperation[operation],'DATA_USE_DENIED','Operation destination is not permitted');
 if(definition.tenantScoped)ensure(/^tenant_[a-z0-9_-]+$/.test(tenantId??''),'TENANT_REQUIRED','Validated tenant boundary required');
 if(operation==='log')ensure(definition.loggable,'DATA_USE_DENIED','Data category is not permitted in application logs');
 if(operation==='model_input')ensure(definition.modelEligible,'DATA_USE_DENIED','Data category is not permitted in model context');
 if(operation==='publish')ensure(definition.classification===DATA_CLASSES.PUBLIC,'DATA_USE_DENIED','Only approved public data may be published');
 return Object.freeze({allow:true,category,classification:definition.classification,tenantId:definition.tenantScoped?tenantId:null,operation,destination:resolvedDestination});
}
