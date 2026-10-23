import test from 'node:test';
import assert from 'node:assert/strict';
import {observeCandidateConnection} from '../host-update-runtime.mjs';
const scope={unit:'styx-owned-test.service',invocationId:'a'.repeat(32),connectorPid:12345,hostId:'owned-host',expectedExecutable:'/owned/release/bin/node',uid:1000};
const row=(status,extra={})=>JSON.stringify({_SYSTEMD_USER_UNIT:scope.unit,_SYSTEMD_INVOCATION_ID:scope.invocationId,_PID:String(scope.connectorPid),_UID:String(scope.uid),_TRANSPORT:'stdout',_EXE:scope.expectedExecutable,MESSAGE:JSON.stringify({host:scope.hostId,lane:'exec',status}),...extra});
test('current systemd invocation connection observation rejects stale identities and follows latest disconnect',()=>{
 const observe=lines=>observeCandidateConnection(scope,{run:(binary,args)=>{assert.equal(binary,'/usr/bin/journalctl');assert.ok(args.includes('_PID=12345'));assert.ok(args.includes('_SYSTEMD_INVOCATION_ID='+scope.invocationId));return lines.join('\n')}});
 assert.equal(observe([row('connected')]),'connected');assert.equal(observe([row('connected'),row('disconnected')]),'disconnected');assert.equal(observe([row('connected'),row('connection_failed')]),'disconnected');assert.equal(observe([]),'unknown');
 for(const changed of [{_SYSTEMD_INVOCATION_ID:'b'.repeat(32)},{_UID:'0'},{_EXE:'/foreign/node'},{_PID:'54321'},{_SYSTEMD_USER_UNIT:'another.service'},{_TRANSPORT:'journal'}])assert.throws(()=>observe([row('connected',changed)]),/observation_unavailable/);
 assert.equal(observe([row('connected',{MESSAGE:JSON.stringify({host:scope.hostId,lane:'computer',status:'connected'})})]),'unknown');
 assert.throws(()=>observe(['invalid JSON']),/observation_unavailable/);
});
