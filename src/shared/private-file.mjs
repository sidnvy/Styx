// Shared facade; implementation also ships beside the standalone installer.
export {requirePrivateFile,requirePrivateDirectory,requirePrivatePaths,ensurePrivateDirectory,openPrivateFile,writePrivateFile}
  from '../host/private-storage.mjs';
