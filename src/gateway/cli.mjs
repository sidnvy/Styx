import fs from 'node:fs';
import {requirePrivateFile} from '../shared/private-file.mjs';
import {fileURLToPath} from 'node:url';
import {createStyxGateway} from './index.mjs';
import {createGatewayHttp} from './http.mjs';
import {EnrollmentController} from './enrollment.mjs';
import {CasExperimentLedger} from './cas/ledger.mjs';

const catalogFile = process.argv[2] || process.env.STYX_TARGETS_FILE;
const tokenFile = process.env.STYX_MCP_TOKEN_FILE;
if (!catalogFile || !tokenFile) {
  process.stderr.write('Required: STYX_MCP_TOKEN_FILE and target catalog path\n');
  process.exit(2);
}
requirePrivateFile(tokenFile);
const catalog = JSON.parse(fs.readFileSync(catalogFile, 'utf8'));
// CAS is a strictly opt-in experiment. The default Gateway surface is unchanged.
const casStateDir = process.env.STYX_CAS_EXPERIMENT_STATE_DIR;
const cas = casStateDir ? await new CasExperimentLedger({directory: casStateDir}).init() : null;
const casOnly = process.env.STYX_CAS_EXPERIMENT_ONLY === '1';
if (casOnly && (!cas || catalog.targets?.length !== 0))
  throw Error('CAS lab-only Gateway requires a private CAS directory and EMPTY target catalog');
const gateway = createStyxGateway({catalog, cas, casOnly});
const enrollmentDir=process.env.STYX_ENROLLMENT_DIR;
const enrollmentAdminFile=process.env.STYX_ENROLL_ADMIN_TOKEN_FILE;
if (Boolean(enrollmentDir)!==Boolean(enrollmentAdminFile))
  throw new Error('Enrollment directory and separate admin token must be configured together');
const enrollment=enrollmentDir
  ?new EnrollmentController({rootDir:enrollmentDir,adminTokenFile:enrollmentAdminFile,
     registry:gateway.registry,relay:gateway.relay})
  :null;
const handle = await createGatewayHttp(gateway, {
  token: fs.readFileSync(tokenFile, 'utf8').trim(),
  host: process.env.STYX_LISTEN_HOST || '127.0.0.1',
  port: Number(process.env.STYX_LISTEN_PORT || 8795),
  allowedHosts: process.env.STYX_ALLOWED_HOSTS?.split(',') || undefined,
  tlsCertificateFile: process.env.STYX_TLS_CERT_FILE || undefined,
  tlsPrivateKeyFile: process.env.STYX_TLS_KEY_FILE || undefined,
  // Production uses bounded idle discovery cleanup; running Exec owners survive.
  ...(casOnly ? {idleSessionTimeoutMs:120000} : {}),
  enrollment
});
process.stdout.write(JSON.stringify({status: 'listening', host: handle.address.address,
  port: handle.address.port, path: '/mcp'}) + '\n');
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    if (stopping) return;
    stopping = true;
    handle.close().then(() => process.exit(0), () => process.exit(1));
  });
}
