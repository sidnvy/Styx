export class ExecError extends Error {
  constructor(code, {session_id, uncertain = false} = {}) {
    super(code); this.code = code; this.session_id = session_id; this.uncertain = uncertain;
  }
}
export class RpcFault extends ExecError {
  constructor(code) { super('executor_rejected'); this.rpcCode = code; }
}
export class TransportFault extends ExecError {
  constructor() { super('transport_unavailable', {uncertain: true}); }
}
