import fs from 'node:fs/promises';
import { build } from '/home/audit/ohscanner/app/web/node_modules/esbuild/lib/main.js';
const root = '/tmp/ohscanner-review-20261016-56o3p1a2';
const mocks = {
'react': `let hook=0;export const changes=[];export const paths=[];export const selectedOld={id:'old-operation'};export function useState(v){const n=hook++;return [n===4?selectedOld:v,n===4?(x)=>changes.push(x.id):()=>{}]};export function useEffect(){};export default {Fragment:'Fragment',createElement:(type,props,...children)=>({type,props:props||{},children})};`,
'antd': `export const Alert='Alert',Button='Button',Card='Card',InputNumber='InputNumber',Select='Select',Space='Space',Table='Table',Tabs='Tabs',Tag='Tag';export const Form=Object.assign('Form',{Item:'Form.Item'});export const Input=Object.assign('Input',{TextArea:'Input.TextArea'});export const Typography={Text:'Text',Title:'Title'};export const message={success:()=>{},error:()=>{}};`,
'../api': `import {paths} from 'react';export const terminal=new Set();export async function api(path,body){paths.push(path);if(body!==undefined)return {id:'new-operation'};if(path.startsWith('/operations/'))return {id:path.slice('/operations/'.length)};return [];}`,
'../components': `export const Header='Header',Hash='Hash';`
};
await build({stdin:{contents:(await fs.readFile('/home/audit/ohscanner/app/web/src/pages/Operations.tsx','utf8'))+"\nexport {changes,paths} from 'react';",loader:'tsx',resolveDir:'/home/audit/ohscanner/app/web/src/pages'},bundle:true,format:'esm',outfile:root+'/handler-replay.mjs',plugins:[{name:'review-mocks',setup(b){b.onResolve({filter:/.*/},args=>args.path in mocks?{path:args.path,namespace:'review'}:undefined);b.onLoad({filter:/.*/,namespace:'review'},args=>({contents:mocks[args.path],loader:'js'}));}}]});
const module=await import(root+'/handler-replay.mjs');
const tree=module.default();
function find(node){if(!node||typeof node!=='object')return null;if(node.type==='Tabs')return node;for(const child of (node.children||[]).flat()){const hit=find(child);if(hit)return hit;}return null;}
const matrix=find(tree).props.items.find(x=>x.key==='matrix');
await matrix.children.props.onFinish({case_id:'case',repository_id:'repo',detector_ids:['d'],commits_text:'a,b',include_paths_text:'.'});
const result={scenario:'An old operation detail is open, then submit a new matrix',selection_writes:module.changes,api_paths:module.paths,kind:'controlled replay of original React handler with mocked hooks and API; not browser E2E'};
await fs.writeFile(root+'/handler-replay-result.json',JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));
