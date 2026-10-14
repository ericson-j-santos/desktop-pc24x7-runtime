'use strict';
// Host-specific GitHub Actions pickup watchdog: no host, deploy or database writes.
const OWNER='ericson-j-santos', REPO='desktop-pc24x7-runtime';
const BRANCH='refs/heads/fix/reqsys-dev-runtime-readonly-inventory-20261014';
const JOB='Inspect only owned ReqSys DEV runtime metadata';
const RUNNER='DESKTOP-PDQK954-runtime', ISSUE=31;
function classify(run,jobs,sha) {
 if(!run||run.head_sha!==sha)return {state:'invalid',reason:'RUN_SHA_MISMATCH'};
 if(run.status==='completed')return {state:'terminal'};
 if(!Array.isArray(jobs))return {state:'invalid',reason:'JOBS_CONTRACT_INVALID'};
 const matching=jobs.filter(j=>j&&j.name===JOB);
 if(matching.length>1)return {state:'invalid',reason:'PHYSICAL_JOB_NOT_UNIQUE'};
 if(matching.length===0)return {state:'waiting'};
 const j=matching[0];
 if(j.run_id!=null&&Number(j.run_id)!==Number(run.id))
   return {state:'invalid',reason:'PHYSICAL_JOB_RUN_MISMATCH'};
 if(j.started_at&&j.runner_name&&j.runner_name!==RUNNER)
   return {state:'invalid',reason:'PHYSICAL_RUNNER_IDENTITY_MISMATCH'};
 if(['in_progress','completed'].includes(j.status)&&j.started_at&&j.runner_name===RUNNER)
   return {state:'picked_up'};
 if(j.status==='completed')return {state:'invalid',reason:'COMPLETED_WITHOUT_PICKUP_PROOF'};
 if(!['queued','pending','waiting','requested','in_progress'].includes(j.status))
   return {state:'invalid',reason:'PHYSICAL_JOB_STATE_INVALID'};
 return {state:'waiting'};
}
async function persistBlock(github,context){
 const marker='<!-- reqsys2546-inventory-pickup-watchdog:'+context.runId+' -->';
 const {owner,repo}=context.repo;
 const comments=await github.paginate(github.rest.issues.listComments,{
   owner,repo,issue_number:ISSUE,per_page:100
 });
 if(comments.some(c=>typeof c.body==='string'&&c.body.includes(marker)))return 'existing';
 const body=[
   marker,'## Desktop inventory pickup blocked','',
   '- Run: https://github.com/'+owner+'/'+repo+'/actions/runs/'+context.runId,
   '- HEAD SHA: '+context.sha,
   '- Reason: SELF_HOSTED_RUNNER_PICKUP_TIMEOUT_OR_BUSY',
   '- No physical pickup verified within 300 seconds.',
   '- No inventory, recovery, database read, deploy, or E2E proven.',
   '- Existing PR remains draft. Do not redispatch without changed precondition.'
 ].join('\n');
 await github.rest.issues.createComment({owner,repo,issue_number:ISSUE,body});
 return 'created';
}
async function monitor({github,context,core,now=()=>Date.now(),
 pause=ms=>new Promise(resolve=>setTimeout(resolve,ms)),timeoutMs=300000,intervalMs=5000}){
 if(!context||context.repo?.owner!==OWNER||context.repo?.repo!==REPO||
    context.ref!==BRANCH||!/^[0-9a-f]{40}$/.test(context.sha||'')||
    !Number.isSafeInteger(context.runId)||context.runId<1){
   core.setFailed('WATCHDOG_SCOPE_INVALID');return 'blocked';
 }
 const args={owner:OWNER,repo:REPO,run_id:context.runId};
 async function observe(){
   const {data:run}=await github.rest.actions.getWorkflowRun(args);
   const {data:{jobs}}=await github.rest.actions.listJobsForWorkflowRun({
     ...args,per_page:100,filter:'latest'
   });
   return classify(run,jobs,context.sha);
 }
 const started=now();
 while(true){
   let state;
   try{state=await observe();}
   catch(_error){core.setFailed('RUNNER_PICKUP_API_UNAVAILABLE');return 'blocked';}
   if(state.state==='picked_up'){
     core.info('PICKUP_VERIFIED: physical E2E and independent readback still required');
     return 'picked_up';
   }
   if(state.state==='terminal')return 'terminal';
   if(state.state==='invalid'){core.setFailed(state.reason);return 'blocked';}
   if(now()-started>=timeoutMs){
     // Re-read before cancellation so a late pickup cannot be cancelled.
     let finalState;
     try{finalState=await observe();}
     catch(_error){core.setFailed('FINAL_PICKUP_READBACK_UNAVAILABLE');return 'blocked';}
     if(finalState.state==='picked_up')return 'picked_up';
     if(finalState.state==='terminal')return 'terminal';
     if(finalState.state!=='waiting'){core.setFailed(finalState.reason);return 'blocked';}
     try{await persistBlock(github,context);}
     catch(_error){core.warning('PICKUP_BLOCK_CHECKPOINT_UNAVAILABLE');}
     try{await github.rest.actions.cancelWorkflowRun(args);}
     catch(_error){core.setFailed('PICKUP_TIMEOUT_CANCEL_NOT_CONFIRMED');return 'blocked';}
     core.setFailed('SELF_HOSTED_RUNNER_PICKUP_TIMEOUT_OR_BUSY');
     return 'cancel_requested';
   }
   await pause(intervalMs);
 }
}
module.exports={classify,persistBlock,monitor};
