import {lstatSync,readdirSync,readFileSync} from 'node:fs';
import {join,relative} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const skipped=new Set(['.git','node_modules','coverage']);
const textFile=/\.(?:cjs|css|html|js|json|md|mjs|ts|tsx|yaml|yml)$/;
const detectors=[
 ['private key',/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
 ['GitHub token',/gh[pousr]_[A-Za-z0-9]{30,}/],
 ['AWS access key',/AKIA[0-9A-Z]{16}/],
 ['credential assignment',/(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['"][^'"\n]{16,}['"]/i]
];

export function scanTextForSecrets(text){
 return detectors.filter(([,pattern])=>pattern.test(text)).map(([name])=>name);
}

function files(directory){
 return readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
  if(skipped.has(entry.name))return [];
  const path=join(directory,entry.name);
  if(entry.isDirectory())return files(path);
  if(!entry.isFile()||!textFile.test(entry.name)||lstatSync(path).size>1_000_000)return [];
  return [path];
 });
}

export function scanRepository(directory=root){
 const failures=[];
 for(const path of files(directory))for(const kind of scanTextForSecrets(readFileSync(path,'utf8'))){
  if(relative(directory,path)==='scripts/scan-secrets.mjs')continue;
  failures.push(`${relative(directory,path)}: possible ${kind}`);
 }
 return failures;
}

if(process.argv[1]&&fileURLToPath(import.meta.url)===fileURLToPath(new URL('file://'+process.argv[1]))){
 const failures=scanRepository();
 if(failures.length){for(const failure of failures)console.error(failure);process.exitCode=1}
 else console.log('Repository secret scan passed.');
}
