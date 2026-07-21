export class SecurityLifecycle {
  #lastActivity = performance.now();
  #lastTick = Date.now();
  #timer: number;
  #locked = false;

  constructor(private readonly lock: (reason: string) => void, private readonly timeoutMs: number) {
    const activity = () => { this.#lastActivity = performance.now(); };
    document.addEventListener("pointerdown", activity, { passive: true, capture: true });
    document.addEventListener("keydown", activity, { capture: true });
    document.addEventListener("visibilitychange", () => { if (document.hidden) this.trigger("page hidden"); });
    window.addEventListener("blur", () => this.trigger("window lost focus"));
    window.addEventListener("pagehide", () => this.trigger("page closed or suspended"));
    window.addEventListener("beforeunload", () => this.trigger("page unloading"));
    document.addEventListener("freeze", () => this.trigger("page frozen"));
    this.#timer = window.setInterval(() => {
      const now = Date.now();
      if (now - this.#lastTick > 15_000) this.trigger("system sleep or workstation lock detected");
      this.#lastTick = now;
      if (performance.now() - this.#lastActivity >= this.timeoutMs) this.trigger("inactivity timeout");
    }, 5_000);
  }

  trigger(reason: string): void {
    if (this.#locked) return;
    this.#locked = true;
    this.lock(reason);
  }

  arm(): void { this.#locked = false; this.#lastActivity = performance.now(); this.#lastTick = Date.now(); }
  destroy(): void { clearInterval(this.#timer); this.trigger("lifecycle destroyed"); }
}
