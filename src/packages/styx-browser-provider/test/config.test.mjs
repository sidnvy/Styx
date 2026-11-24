import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {normalizeBrowserConfig} from '../config.mjs';

test('Browser config is independent of computer, uses private profile root, and has no new connection-count policy',()=>{
  assert.equal(normalizeBrowserConfig(undefined),null);assert.equal(normalizeBrowserConfig({enabled:false}),null);
  const profileRoot=path.resolve('/private/browser');
  assert.deepEqual(normalizeBrowserConfig({enabled:true,profileRoot}),{enabled:true,profileRoot,headless:true});
  for(const browser of [{enabled:true,profileRoot:'relative'},{enabled:true,profileRoot,maxSessions:1},{enabled:true,profileRoot,cdpEndpoint:'http://127.0.0.1:9222'},{enabled:true,profileRoot,headless:'yes'}])assert.throws(()=>normalizeBrowserConfig(browser));
});
