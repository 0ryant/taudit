export function isSupportedPipelinePath(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  return lower.endsWith(".yml") || lower.endsWith(".yaml");
}
