'use strict';
// Entry point: `node test.cjs`. Legacy checks first, then every tests/*.test.cjs (REQUIREMENTS.md).
const test=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');const read=n=>fs.readFileSync(path.join(__dirname,n),'utf8'),ctx={};vm.createContext(ctx);vm.runInContext(read('core.js'),ctx);const map=ctx.registry(read('catalog.txt'));const parse=s=>ctx.parse(s,map);
test('legacy: OT example, quotes, scan groups, CIDRs, exclusions, arity inventory',()=>{
const ot=parse('nmap -sT -n -p 102,502,2404,4840,20000,44818 --max-rate 10 --max-retries 1 -iL ot-ranges.txt --excludefile exclude.txt -oA $R/ot-find');
assert.equal(ot.issues.length,0);assert.equal(ot.flags.length,8);assert.equal(ot.flags.at(-1).val,'$R/ot-find');assert.match(ctx.scope(ot,new Map()),/unknown/);assert.match(ctx.scope(ot,new Map([['ot-ranges.txt','10.10.10.0/24'],['exclude.txt','10.10.10.1']])),/^255 distinct/);
assert.deepEqual(Array.from(parse('nmap -sSU -PS22,443 -p- -T4 --script="default and safe" -oX "my report.xml" example.test').flags,a=>a.key),['-sS','-sU','-PS','-p','-T','--script','-oX']);assert.equal(parse('nmap -oX "my report.xml" example.test').flags[0].val,'my report.xml');assert.ok(parse('nmap --made-up 10.0.0.1').issues.length);assert.ok(parse('nmap --max-rate -Pn 10.0.0.1').issues.length);assert.ok(parse('nmap -6 -4 example.test').issues.length);assert.match(ctx.scope(parse('nmap -sn 0.0.0.0/0 --exclude 0.0.0.0/1'),new Map()),/^2,147,483,648/);
for(const d of map.values()){const p=parse('nmap '+d.key+(d.arg==='required'?' 1':'')+' 10.0.0.1');assert.equal(p.flags[0].def.key,d.key);if(d.arg==='required')assert.equal(p.flags[0].val,'1');}for(const line of read('coverage.txt').split('Source registration → argument type\n')[1].trim().split('\n')){const [name,arity]=line.split(' '),d=map.get('--'+name)||map.get('-'+name);assert.equal(d.arg,{required:'required',no:'none',optional:'attached'}[arity]);}
});
for(const f of fs.readdirSync(path.join(__dirname,'tests')).filter(f=>f.endsWith('.test.cjs')).sort())require(path.join(__dirname,'tests',f));
