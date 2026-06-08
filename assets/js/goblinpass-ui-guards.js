(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  function setHidden(id, hidden) {
    const el = $(id);
    if (el) el.classList.toggle("hidden", hidden);
  }

  function wireYubiKeyReveal() {
    const toggle = $("useYubiKey");
    if (!toggle) return;
    const sync = () => setHidden("yubiKeyBox", !toggle.checked);
    toggle.addEventListener("change", sync);
    sync();
  }

  function wireSecurityKeyReveal() {
    const toggle = $("enableSecurityKey");
    if (!toggle) return;
    const sync = () => {
      setHidden("securityKeyBox", !toggle.checked);
      setHidden("securityKeyMethodGroup", !toggle.checked);
      setHidden("securityKeyWarning", !toggle.checked);
      const method = $("securityKeyInputMethod");
      if (method) method.disabled = !toggle.checked;
    };
    toggle.addEventListener("change", sync);
    sync();
  }

  function wireTrustedDeviceReveal() {
    const toggle = $("enableTrustedDevice");
    if (!toggle) return;
    const sync = () => {
      setHidden("trustedDeviceDetails", !toggle.checked);
      setHidden("trustedDeviceWarning", !toggle.checked);
    };
    toggle.addEventListener("change", sync);
    sync();
  }

  function wireGoogleReveal() {
    const toggle = $("googleSecurityFactor");
    if (!toggle) return;
    const sync = () => setHidden("googleSecurityWarning", !toggle.checked);
    toggle.addEventListener("change", sync);
    sync();
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireYubiKeyReveal();
    wireSecurityKeyReveal();
    wireTrustedDeviceReveal();
    wireGoogleReveal();
  });
})();
