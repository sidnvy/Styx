import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {soakOptions} from '../exec-soak.mjs';
test('soak has a bounded native-only duration and requires a fresh absolute state root',()=>{
  const directory=path.join(os.tmpdir(),'styx-soak-unit-not-created');
  assert.deepEqual(soakOptions({directory}),{directory,durationSeconds:86400,intervalSeconds:60});
  for(const option of [{directory:'relative'}, {directory,durationSeconds:0},
    {directory,durationSeconds:Infinity},{directory,durationSeconds:172801},
    {directory,intervalSeconds:0},{directory,intervalSeconds:3601}]){
    assert.throws(()=>soakOptions(option));
  }
});
