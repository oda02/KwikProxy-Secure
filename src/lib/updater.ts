/**
 * Fail-closed updater facade.
 *
 * This fork does not yet have its own production release-signing key and
 * protected per-machine update lifecycle. Keeping the upstream endpoint or
 * updater plugin active would let upstream release metadata control this
 * fork. This module therefore performs no network, download, process,
 * service, or install action.
 */

export interface AvailableUpdate {
  version: string;
  currentVersion: string;
  notes: string;
  date: string | null;
}

export const UPDATER_ENABLED = false;

/** No network check is permitted while the updater trust chain is disabled. */
export async function checkForUpdates(): Promise<AvailableUpdate | null> {
  throw updaterDisabled();
}

function updaterDisabled(): Error {
  return new Error(
    "In-app updates are disabled until fork releases and the installer are independently signed."
  );
}

export async function downloadUpdate(
  _update: AvailableUpdate,
  _onProgress?: (fraction: number) => void
): Promise<void> {
  throw updaterDisabled();
}

export async function installUpdate(_update: AvailableUpdate): Promise<void> {
  throw updaterDisabled();
}
