import test from 'node:test';
import assert from 'node:assert/strict';
import {summarizeTap} from '../../ci/acceptance.mjs';
const tap=({pass=1,fail=0,skipped=0,cancelled=0,todo=0}={})=>
  Object.entries({tests:pass+fail+skipped+cancelled+todo,pass,fail,cancelled,skipped,todo})
    .map(([key,value])=>'# '+key+' '+value).join('\n')+'\n';
test('acceptance evidence preserves skipped counts without accepting an all-skipped run',()=>{
  assert.equal(summarizeTap(tap({pass:0,skipped:3}),0).status,'NOT RUN');
  assert.deepEqual(summarizeTap(tap({skipped:2}),0),{
    status:'PASS',tests:3,pass:1,fail:0,cancelled:0,skipped:2,todo:0});
});
test('failed, cancelled, malformed and interrupted runs cannot pass acceptance',()=>{
  for(const [text,code] of [[tap({fail:1}),0],[tap({cancelled:1}),0],
    [tap(),1],[tap(),null],['',0],['# tests 5\n'+tap(),0]]){
    assert.equal(summarizeTap(text,code).status,'FAIL');
  }
  assert.equal(summarizeTap(tap().replaceAll('\n','\r\n'),0).status,'PASS');
});
