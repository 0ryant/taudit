import * as fs from "node:fs/promises";

export async function existingArtifactPath(
  candidate: string | undefined,
): Promise<string | undefined> {
  if (!candidate) {
    return undefined;
  }

  try {
    await fs.access(candidate);
    return candidate;
  } catch {
    return undefined;
  }
}
