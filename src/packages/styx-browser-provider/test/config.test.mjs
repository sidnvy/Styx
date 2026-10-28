import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeBrowserConfig} from '../config.mjs';

test('Browser config is independent of computer, uses private profile root, and has no new connection-count policy',()=>{
  assert.equal(normalizeBrowserConfig(undefined),null);assert.equal(normalizeBrowserConfig({enabled:false}),null);
  assert.deepEqual(normalizeBrowserConfig({enabled:true,profileRoot:'/private/browser'}),{enabled:true,profileRoot:'/private/browser',headless:true});
  for(const browser of [{enabled:true,profileRoot:'relative'},{enabled:true,profileRoot:'/private/browser',maxSessions:1},{enabled:true,profileRoot:'/private/browser',cdpEndpoint:'http://127.0.0.1:9222'},{enabled:true,profileRoot:'/private/browser',headless:'yes'}])assert.throws(()=>normalizeBrowserConfig(browser));
});
