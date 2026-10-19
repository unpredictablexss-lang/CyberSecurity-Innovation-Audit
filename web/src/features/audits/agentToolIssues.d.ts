export function agentToolIssues(toolCalls: unknown): Array<{
  tool: string; status: string; errorCode: string; message: string;
}>;
