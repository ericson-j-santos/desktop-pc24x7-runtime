'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {classify,persistBlock,monitor}=require('../scripts/reqsys_dev_inventory_pickup_watchdog.cjs');
const sha='a'.repeat(40);
const context={repo:{owner:'ericson-j-santos',repo:'desktop-pc24x7-runtime'},
 ref:'refs/heads/fix/reqsys-dev-runtime-readonly-inventory-20261014',sha,runId:38628175067};
const job=(x={})=>({name:'Inspect only owned ReqSys DEV runtime metadata',
 run_id:context.runId,status:'queued',started_at:null,runner_name:null,...x});
const run=(x={})=>({id:context.runId,head_sha:sha,status:'in_progress',...x});
const core=()=>({fails:[],infos:[],warnings:[],setFailed(v){this.fails.push(v)},
 info(v){this.infos.push(v)},warning(v){this.warnings.push(v)}});
function fixture(jobs=[job()],comments=[]){
 const calls={cancel:0,comments:0,reads:0};
 const github={paginate:async()=>comments,rest:{
  actions:{
   getWorkflowRun:async()=>({data:run()}),
   listJobsForWorkflowRun:async()=>{calls.reads++;return {data:{jobs}};},
   cancelWorkflowRun:async()=>{calls.cancel++;return {status:202};}
  },
  issues:{listComments(){},createComment:async()=>{calls.comments++;return {data:{id:1}};}}
 }};
 return {github,calls};
}
test('positive pickup requires exact physical runner and started_at',()=>{
 assert.equal(classify(run(),[job({status:'in_progress',started_at:'now',
  runner_name:'DESKTOP-PDQK954-runtime'})],sha).state,'picked_up');
 assert.equal(classify(run(),[job({status:'in_progress',started_at:'now'})],sha).state,'waiting');
 assert.equal(classify(run(),[job({status:'completed',conclusion:'skipped'})],sha).reason,
  'COMPLETED_WITHOUT_PICKUP_PROOF');
 assert.equal(classify(run(),[job({status:'in_progress',started_at:'now',runner_name:'wrong'})],sha).reason,
  'PHYSICAL_RUNNER_IDENTITY_MISMATCH');
});
test('SHA, job multiplicity and run identity failures are detected',()=>{
 assert.equal(classify(run(),[job()],'b'.repeat(40)).reason,'RUN_SHA_MISMATCH');
 assert.equal(classify(run(),[job(),job()],sha).reason,'PHYSICAL_JOB_NOT_UNIQUE');
 assert.equal(classify(run(),[job({run_id:77})],sha).reason,'PHYSICAL_JOB_RUN_MISMATCH');
 assert.equal(classify(run({status:'completed'}),[job()],sha).state,'terminal');
});
test('300s stall persists one checkpoint and cancels once',async()=>{
 const {github,calls}=fixture();let now=0;const c=core();
 assert.equal(await monitor({github,context,core:c,now:()=>now,pause:async ms=>{now+=ms;}}),'cancel_requested');
 assert.equal(now,300000);assert.equal(calls.cancel,1);assert.equal(calls.comments,1);
 assert.deepEqual(c.fails,['SELF_HOSTED_RUNNER_PICKUP_TIMEOUT_OR_BUSY']);
 assert.ok(calls.reads>=3);
});
test('idempotent checkpoint avoids duplicate comments',async()=>{
 const {github,calls}=fixture([], [{body:'<!-- reqsys2546-inventory-pickup-watchdog:'+context.runId+' -->'}]);
 assert.equal(await persistBlock(github,context),'existing');
 assert.equal(calls.comments,0);
});
test('successful pickup does not cancel or claim E2E',async()=>{
 const {github,calls}=fixture([job({status:'in_progress',started_at:'now',
  runner_name:'DESKTOP-PDQK954-runtime'})]);const c=core();
 assert.equal(await monitor({github,context,core:c}),'picked_up');
 assert.equal(calls.cancel,0);assert.deepEqual(c.fails,[]);
 assert.match(c.infos[0],/E2E and independent readback still required/);
});
test('unauthorized scope blocks before GitHub API',async()=>{
 const {github,calls}=fixture();const c=core();
 assert.equal(await monitor({github,context:{...context,ref:'refs/heads/main'},core:c}),'blocked');
 assert.equal(calls.reads,0);assert.equal(calls.cancel,0);
 assert.deepEqual(c.fails,['WATCHDOG_SCOPE_INVALID']);
});
test('API failure never reports success or leaks secrets',async()=>{
 const {github,calls}=fixture();const c=core();
 github.rest.actions.getWorkflowRun=async()=>{throw new Error('secret-marker');};
 assert.equal(await monitor({github,context,core:c}),'blocked');
 assert.equal(calls.cancel,0);assert.deepEqual(c.fails,['RUNNER_PICKUP_API_UNAVAILABLE']);
 assert.equal(JSON.stringify(c).includes('secret-marker'),false);
});
test('late physical pickup on final readback suppresses cancellation',async()=>{
 const {github,calls}=fixture();let n=0,now=0;const c=core();
 github.rest.actions.listJobsForWorkflowRun=async()=>{
  n++;return {data:{jobs:[job(n>=4?
   {status:'in_progress',started_at:'now',runner_name:'DESKTOP-PDQK954-runtime'}:{})]}};};
 assert.equal(await monitor({github,context,core:c,now:()=>now,
  pause:async ms=>{now+=ms;},timeoutMs:10000}),'picked_up');
 assert.equal(calls.cancel,0);assert.equal(calls.comments,0);
});
test('cancel authorization failure is not declared completed',async()=>{
 const {github,calls}=fixture();let now=0;const c=core();
 github.rest.actions.cancelWorkflowRun=async()=>{throw new Error('private-token')};
 assert.equal(await monitor({github,context,core:c,now:()=>now,
  pause:async ms=>{now+=ms;},timeoutMs:10000}),'blocked');
 assert.equal(c.fails.at(-1),'PICKUP_TIMEOUT_CANCEL_NOT_CONFIRMED');
 assert.equal(calls.comments,1);assert.equal(JSON.stringify(c).includes('private-token'),false);
});
