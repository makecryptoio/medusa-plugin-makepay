import assert from "node:assert/strict";
import { chmod, lstat, rm, stat } from "node:fs/promises";
import { createServer } from "node:net";
import test from "node:test";

import {
  createRestrictedSocketAddress,
  macOsUnixSocketPathLimit,
} from "./e2e/support/restricted-socket.mjs";

test("old signer uses a short owner-private socket directory on macOS", async () => {
  const longWorkspaceTemporaryDirectory =
    "/private/var/folders/example/T/" + "makepay-medusa-e2e-".repeat(8);
  const location = await createRestrictedSocketAddress("old-b", {
    platform: "darwin",
    temporaryDirectory: longWorkspaceTemporaryDirectory,
  });

  try {
    assert.match(location.socketDirectory, /^\/tmp\/mpe2e-/);
    assert.equal(
      Buffer.byteLength(location.socketPath) < macOsUnixSocketPathLimit,
      true,
    );
    const directory = await lstat(location.socketDirectory);
    assert.equal(directory.isDirectory(), true);
    assert.equal(directory.isSymbolicLink(), false);
    assert.equal(directory.mode & 0o777, 0o700);
    if (typeof process.getuid === "function") {
      assert.equal(directory.uid, process.getuid());
    }

    const server = createServer();
    try {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(location.socketPath, () => {
          server.off("error", reject);
          resolve();
        });
      });
      await chmod(location.socketPath, 0o600);
      const socket = await stat(location.socketPath);
      assert.equal(socket.isSocket(), true);
      assert.equal(socket.mode & 0o777, 0o600);
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  } finally {
    await rm(location.socketDirectory, { force: true, recursive: true });
  }
});
