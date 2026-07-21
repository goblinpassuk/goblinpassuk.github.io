import { constantTimeEqual, utf8, wipe } from "./crypto.js";

export class SecureClipboard {
  #timer: number | null = null;
  #lastCopyAt = 0;
  #expectedBytes: Uint8Array | null = null;
  constructor(public clearAfterMs = 30_000, readonly recopyCooldownMs = 1_500) {}

  async copy(secret: string, status: (message: string, warning: boolean) => void): Promise<void> {
    const now = Date.now();
    if (now - this.#lastCopyAt < this.recopyCooldownMs) throw new DOMException("Please wait before copying again.", "InvalidStateError");
    await navigator.clipboard.writeText(secret);
    this.#lastCopyAt = now;
    this.cancel();
    this.#expectedBytes = utf8(secret);
    this.#timer = window.setTimeout(() => void this.#clearIfUnchanged(status), this.clearAfterMs);
  }

  async #clearIfUnchanged(status: (message: string, warning: boolean) => void): Promise<void> {
    this.#timer = null;
    const expectedBytes = this.#expectedBytes;
    this.#expectedBytes = null;
    if (!expectedBytes) return;
    let currentBytes: Uint8Array | undefined;
    try {
      const current = await navigator.clipboard.readText();
      currentBytes = utf8(current);
      if (!constantTimeEqual(expectedBytes, currentBytes)) {
        status("Clipboard changed, so GoblinPass did not overwrite it.", false);
        return;
      }
      await navigator.clipboard.writeText("");
      status("Clipboard cleared after the configured timeout.", false);
    } catch {
      status("GoblinPass could not verify or clear the clipboard. Clear clipboard history manually.", true);
    } finally {
      wipe(expectedBytes, currentBytes);
    }
  }

  cancel(): void {
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
    wipe(this.#expectedBytes ?? undefined);
    this.#expectedBytes = null;
  }
}
