const str = {type: 'string'}, num = {type: 'number'}, bool = {type: 'boolean'};
const outputSchema = {
  type: 'object', additionalProperties: false, required: ['wall_time_seconds', 'output'],
  properties: {chunk_id: str, wall_time_seconds: num, exit_code: num, session_id: num,
    original_token_count: num, output: str}
};
export const tools = [
  {name: 'exec_command', description: 'Run a command; return output or an owned interactive session.',
    inputSchema: {type: 'object', additionalProperties: false, required: ['cmd'],
      properties: {cmd: str, workdir: str, shell: str, login: bool, tty: bool,
        yield_time_ms: num, max_output_tokens: num, environment_id: str}}, outputSchema},
  {name: 'write_stdin', description: 'Write to an owned session, or poll with empty chars.',
    inputSchema: {type: 'object', additionalProperties: false, required: ['session_id'],
      properties: {session_id: num, chars: str, yield_time_ms: num, max_output_tokens: num}}, outputSchema}
];
