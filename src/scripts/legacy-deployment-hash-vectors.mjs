// Development-only differential oracle; never included in the Rust runtime.
import { deploymentConnectionHash } from '../shared/deployment-scope.mjs';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
const vectors = [
 ['host_only_original_bytes', '{ "mode": "join-existing", "gateway": {"origin":"https://fixture.invalid"} }\r\n'],
 ['gateway_without_ingress', '{"mode":"create-local","gateway":{"port":8443}}\n'],
 ['default_local_with_ingress', '{"schema":1,"mode":"create-local","gateway":{"port":8443,"deviceIngress":{"port":8444},"host":"127.0.0.1"},"host":{"enabled":true}}'],
 ['null_ingress_still_deleted', '{"gateway":{"deviceIngress":null,"port":8443},"enabled":false}'],
 ['decoded_duplicate_keys', '{"gateway":{"port":1,"deviceIngress":true},"gate\\u0077ay":{"deviceIngress":false,"port":2},"x":1,"x":2}'],
 ['numeric_property_order', '{"10":"ten","2":"two","01":"text","4294967295":"notIndex","gateway":{"10":1,"2":2,"deviceIngress":true,"0":0}}'],
 ['unicode_and_control_escaping', JSON.stringify({label:'Styx 中文 😀 / \u2028 \u2029 \b\f\n\r\t\u0000',gateway:{deviceIngress:{enabled:true}},nested:[{},[],null,true,false]})],
 ['binary64_and_exponents', '{"gateway":{"deviceIngress":true},"numbers":[-0,1.0,1e-7,1e-6,1e20,1e21,9007199254740993,1e400,-1e400,5e-324,1.2345678901234567,1000000000000000128]}'],
 ['nested_ingress_is_preserved', '{"gateway":{"deviceIngress":{},"nested":{"deviceIngress":{"token":"fixture"}}},"deviceIngress":"outside"}'],
 ['gateway_null_unchanged', ' {"gateway":null,"value":1.0}\n'],
 ['empty_gateway_after_delete', '{"gateway":{"deviceIngress":true}}'],
 ['array_and_prototype_keys', '{"gateway":{"deviceIngress":false},"__proto__":{"a":1},"data":[{"4":0,"1":1,"b":2,"a":3}]}']
].map(([id,input])=>({id,input,sha256:deploymentConnectionHash(Buffer.from(input))}));
const output={schema:1,oracle:'src/shared/deployment-scope.mjs',oracle_sha256:createHash('sha256').update(readFileSync(new URL('../shared/deployment-scope.mjs',import.meta.url))).digest('hex'),vectors};
writeFileSync(new URL('../docs/rust-core-rewrite/LEGACY-DEPLOYMENT-HASH-VECTORS.json',import.meta.url),JSON.stringify(output,null,2)+'\n');
console.log(JSON.stringify({vectors:vectors.length,oracle_sha256:output.oracle_sha256}));
