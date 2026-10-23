// Protocol fixture only: bypasses physical desktop admission by directly
// invoking injected fake Cua transport. Native tests use the production entry.
import fs from 'node:fs';
import {runHostConnector} from '../../../host/connect.mjs';
import {runComputerConnectors} from '../../../host/computer.mjs';
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const abort=new AbortController();
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>abort.abort());
await Promise.all([runHostConnector(config,{signal:abort.signal}),runComputerConnectors(config,{signal:abort.signal})]);
