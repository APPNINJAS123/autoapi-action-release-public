export interface ChangeEventEvidenceBoundary {
  evidence: ReadonlyArray<{ url: string; contentHash: string }>;
  provenanceHash: string;
}

export function assertNonSyntheticChangeEvent(
  event: ChangeEventEvidenceBoundary,
  source: string,
): void {
  const hashes = [...event.evidence.map(item => item.contentHash), event.provenanceHash];
  const placeholderHash = hashes.find(hash => /^([0-9a-f])\1{63}$/u.test(hash));
  const placeholderUrl = event.evidence.find(item => new URL(item.url).hostname === "example.com");
  if (placeholderHash || placeholderUrl) {
    throw new Error(`${source}: synthetic or placeholder evidence is not accepted`);
  }
}
