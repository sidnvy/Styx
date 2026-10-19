// Fixed service entry; no arbitrary command dispatch and no credential output.
import {startDeploymentGateway,stopDeploymentGateway} from './core.mjs';
const state=process.argv[2];
try{
 if(process.argv.length!==3)throw Error('state_directory_required');
 await startDeploymentGateway(state);
 let stopping=false;
 const stop=()=>{if(stopping)return;stopping=true;stopDeploymentGateway(state).then(()=>process.exit(0),()=>process.exit(2))};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 process.stdout.write('Styx Gateway running.\n');
}catch{process.stderr.write('Styx Gateway startup failed; inspect private deployment state.\n');process.exitCode=2;}
