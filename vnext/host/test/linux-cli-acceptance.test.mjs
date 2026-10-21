import test from 'node:test';
import assert from 'node:assert/strict';
import {linuxAcceptancePaths,linuxAcceptanceReference,runLinuxCliAcceptance} from '../linux-cli-acceptance.mjs';
test('native Linux acceptance requires isolated sibling paths and explicit opt-in',async()=>{
 assert.throws(()=>linuxAcceptancePaths({directory:'/tmp/package/result',distribution:'/tmp/package'},'linux','x64'),/independent_acceptance_directory_required/);
 assert.throws(()=>linuxAcceptancePaths({directory:'relative',distribution:'/tmp/package'},'linux','x64'),/absolute_acceptance_paths_required/);
 assert.throws(()=>linuxAcceptancePaths({directory:'/tmp/result',distribution:'/tmp/package'},'win32','x64'),/linux_x64_acceptance_required/);
 assert.deepEqual(linuxAcceptancePaths({directory:'/tmp/result',distribution:'/tmp/package'},'linux','x64'),{directory:'/tmp/result',distribution:'/tmp/package'});
 const original=process.env.STYX_RUN_LINUX_CLI_ACCEPTANCE;delete process.env.STYX_RUN_LINUX_CLI_ACCEPTANCE;
 try{await assert.rejects(runLinuxCliAcceptance({}),/explicit_linux_cli_acceptance_required/);}finally{if(original!==undefined)process.env.STYX_RUN_LINUX_CLI_ACCEPTANCE=original;}
});
test('browser acceptance resolves only the named observed opaque reference',()=>{
 const result={content:[{type:'text',text:'- textbox "Name" [ref=styx-123456abcdef]\n- button "Store" [ref=styx-abcdef123456]'}]};
 assert.equal(linuxAcceptanceReference(result,'Name'),'styx-123456abcdef');
 assert.equal(linuxAcceptanceReference(result,'Store'),'styx-abcdef123456');
 assert.throws(()=>linuxAcceptanceReference(result,'Other'),/owned_browser_reference_missing/);
});
