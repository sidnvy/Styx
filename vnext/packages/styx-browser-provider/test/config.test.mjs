import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeBrowserConfig} from '../config.mjs';
import {browserConfig} from '../../../host/browser.mjs';

test('Browser config is independent of computer, uses private profile root, and has no new connection-count policy',()=>{
  assert.equal(normalizeBrowserConfig(undefined),null);assert.equal(normalizeBrowserConfig({enabled:false}),null);
  assert.deepEqual(normalizeBrowserConfig({enabled:true,profileRoot:'/private/browser'}),{enabled:true,profileRoot:'/private/browser',headless:true});
  for(const browser of [{enabled:true,profileRoot:'relative'},{enabled:true,profileRoot:'/private/browser',maxSessions:1},{enabled:true,profileRoot:'/private/browser',cdpEndpoint:'http://127.0.0.1:9222'},{enabled:true,profileRoot:'/private/browser',headless:'yes'}])assert.throws(()=>normalizeBrowserConfig(browser));
  const config={host_id:'a',gateway_ws_url:'wss://example.test',token_file:'/private/token',exec:{binary:'/private/codex',cwd:'/private/work'},browser:{enabled:true,profileRoot:'/private/browser'}};
  assert.equal(browserConfig(config).browserEndpoint,'wss://example.test/styx/hosts/a/browser');assert.equal(browserConfig({...config,browser:{enabled:false}}),null);
});
