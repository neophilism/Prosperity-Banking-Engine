import {mkdirSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';

const fail=message=>{throw new Error(message)};
if(process.env.DATA_MODE!=='synthetic')fail('CI data mode must be synthetic');
if(!/^ci-[0-9]+-[0-9]+$/.test(process.env.PROSPERITY_ENVIRONMENT??''))fail('Unique CI environment identity required');
for(const name of ['DATABASE_URL','BANK_API_KEY','BANK_CLIENT_SECRET','PRODUCTION_TENANT_ID']){
 if(process.env[name])fail(`${name} is forbidden in synthetic CI`);
}
const directory=resolve(process.env.ENGINE_EPHEMERAL_DIR??'');
if(!process.env.RUNNER_TEMP||!directory.startsWith(resolve(process.env.RUNNER_TEMP)+'/'))fail('Ephemeral directory must be inside RUNNER_TEMP');
mkdirSync(directory,{recursive:true});
if(readdirSync(directory).length)fail('Ephemeral directory must start empty');
writeFileSync(resolve(directory,'synthetic-marker.json'),JSON.stringify({mode:'synthetic'}));
rmSync(directory,{recursive:true,force:true});
console.log('Synthetic ephemeral CI environment validated and removed.');
