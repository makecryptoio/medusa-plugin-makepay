import { chmod, lstat, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const macOsUnixSocketPathLimit = 104;

export async function createRestrictedSocketAddress(
  name,
  {
    platform = process.platform,
    temporaryDirectory = tmpdir(),
  } = {},
) {
  if (!/^[a-z0-9_-]{1,32}$/i.test(name)) {
    throw new Error("Restricted socket name is invalid.");
  }

  // Darwin's sockaddr_un.sun_path is only 104 bytes. Keep sockets out of the
  // potentially long per-user TMPDIR used by the disposable Medusa workspace.
  const socketBase = platform === "win32" ? temporaryDirectory : "/tmp";
  const socketDirectory = await mkdtemp(join(socketBase, "mpe2e-"));
  try {
    await chmod(socketDirectory, 0o700);
    const directoryEntry = await lstat(socketDirectory);
    if (
      !directoryEntry.isDirectory() ||
      directoryEntry.isSymbolicLink() ||
      (typeof process.getuid === "function" &&
        directoryEntry.uid !== process.getuid())
    ) {
      throw new Error(
        "The E2E control-socket directory is not a private directory.",
      );
    }

    const socketPath = join(
      await realpath(socketDirectory),
      `${name}.sock`,
    );
    if (
      platform === "darwin" &&
      Buffer.byteLength(socketPath) >= macOsUnixSocketPathLimit
    ) {
      throw new Error("The E2E Unix-socket path exceeds the macOS limit.");
    }
    return { socketDirectory, socketPath };
  } catch (error) {
    await rm(socketDirectory, { force: true, recursive: true });
    throw error;
  }
}
