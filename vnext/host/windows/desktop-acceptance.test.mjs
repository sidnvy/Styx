import test from 'node:test';
import assert from 'node:assert/strict';
import {runOwnedDesktopAcceptance} from './desktop-acceptance.mjs';
test('own-window Cua harness requires explicit native authorization before any file or desktop action',async()=>{await assert.rejects(runOwnedDesktopAcceptance({authorizeOwnedDesktop:false}),/explicit_native_owned_desktop_required/);});
