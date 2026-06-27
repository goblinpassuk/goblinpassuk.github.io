(function () {
  "use strict";

  const $ = id => document.getElementById(id);

  class Level2SecurityMapTest {
    constructor() {
      this.dbName = "GoblinPassLevel2TestDB";
      this.storeName = "level2State";
      this.fileHandleId = "level2-state-file-handle";
      this.localStorageKey = "goblinpass_level2_test_encrypted_record";
      this.credentialStorageKey = "goblinpass_level2_test_prf_credential";
      this.trustedDeviceStorageKey = "goblinpass_level2_test_trusted_device_key_v1";
      this.trustedDeviceBackedUpKey = "goblinpass_level2_test_trusted_device_backed_up_v1";
      this.exportType = "goblinpass-security-map";
      this.stateFileName = "goblinpass-stateless-gen2-beta-state.json";
      this.dataVersion = 1;
      this.rows = [];
      this.db = null;
      this.cryptoKey = null;
      this.credentialId = null;
      this.isUnlocked = false;
      this.autoRecord = true;
      this.generatedPassword = "";
      this.generatedVisible = false;
      this.masterVisible = false;
      this.mapRevealAll = false;
      this.revealedRowKeys = new Set();
      this.editingRowKey = null;
      this.siteFilter = "";
      this.currentPage = 1;
      this.pageSize = 25;
      this.layoutStorageKey = "goblinpass_level2_test_layout_v2";
      this.googleClientId = "908605927082-sne248f74g829ek1kh1mh11gumjj411m.apps.googleusercontent.com";
      this.googleScriptPromise = null;
      this.googleUser = null;
      this.stateFileHandle = null;
      this.fileSystemAccessSupported = "showOpenFilePicker" in window && "showSaveFilePicker" in window;
      this.icons = [
        { id: "google-factor", title: "Google factor", className: "icon-google-factor-vector" },
        { id: "yubikey", title: "YubiKey", className: "icon-yubikey-vector" },
        { id: "master-password", title: "Master Password", className: "icon-master-password-vector" },
        { id: "trusted-device-id", title: "Trusted device ID", className: "icon-trusted-device-vector" },
        { id: "copy-password-only", title: "Copy password only", className: "icon-copy-only-vector" }
      ];
      this.dbReady = this.initDatabase();
      this.bindEvents();
      this.clearStarterAccountFields();
      this.renderLegend();
      this.renderRows();
      this.initStateFileControls();
      this.updateUI();
    }

    clearStarterAccountFields() {
      $("level2SiteId").value = "";
      $("level2Site").value = "";
    }

    bindEvents() {
      $("level2Register").addEventListener("click", () => this.registerTestState());
      $("level2OpenState").addEventListener("click", () => this.openStateFile());
      $("level2Reconnect").addEventListener("click", () => this.reconnectStateFile());
      $("level2SaveState").addEventListener("click", () => this.saveToOpenedStateFile());
      $("level2SaveAs").addEventListener("click", () => this.saveAsNewStateFile());
      $("level2Export").addEventListener("click", () => this.exportState());
      $("level2Generate").addEventListener("click", () => this.generateAndMaybeRecord());
      $("level2AutoRecord").addEventListener("click", () => this.toggleAutoRecord());
      $("level2ToggleMapReveal").addEventListener("click", () => this.toggleMapRevealAll());
      $("level2SiteFilter").addEventListener("input", event => this.updateSiteFilter(event.target.value));
      $("level2PageSize").addEventListener("change", event => this.updatePageSize(event.target.value));
      $("level2PrevPage").addEventListener("click", () => this.changePage(-1));
      $("level2NextPage").addEventListener("click", () => this.changePage(1));
      $("level2CopyPassword").addEventListener("click", () => this.copyGeneratedPassword());
      $("level2TogglePassword").addEventListener("click", () => this.toggleGeneratedPassword());
      $("level2ToggleMaster").addEventListener("click", event => {
        event.preventDefault();
        event.stopPropagation();
        this.toggleMasterVisibility();
      });
      $("level2RequireMaster").addEventListener("change", () => this.updateMasterRequirement());
      $("level2Style").addEventListener("change", () => this.updatePasswordStyleFields());
      $("level2MethodGoogle").addEventListener("change", () => {
        this.updateSettingsReveals();
        this.updateGoogleStatus();
      });
      $("level2GoogleSetup").addEventListener("click", () => this.setupGoogleSignIn());
      $("level2GoogleSignOut").addEventListener("click", () => this.googleSignOut());
      $("level2MethodTrusted").addEventListener("change", () => this.updateTrustedDeviceSetting());
      $("level2ShowRecoveryKey").addEventListener("click", () => this.showTrustedRecoveryKey());
      $("level2RestoreTrustedDevice").addEventListener("click", () => this.restoreTrustedDevice());
      $("level2MethodCopyOnly").addEventListener("change", () => this.updateUI());
      document.querySelectorAll("[data-level2-layout]").forEach(button => {
        button.addEventListener("click", () => this.setLayout(button.dataset.level2Layout));
      });
      document.querySelectorAll("[data-level2-panel]").forEach(button => {
        button.addEventListener("click", () => this.showPanel(button.dataset.level2Panel));
      });
      $("navToggle")?.addEventListener("click", () => {
        const expanded = $("navToggle").getAttribute("aria-expanded") === "true";
        $("navToggle").setAttribute("aria-expanded", String(!expanded));
        $("navLinks")?.classList.toggle("open", !expanded);
      });
    }

    async initDatabase() {
      return new Promise(resolve => {
        const request = indexedDB.open(this.dbName, 1);
        request.onupgradeneeded = event => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(this.storeName)) db.createObjectStore(this.storeName, { keyPath: "id" });
        };
        request.onsuccess = event => {
          this.db = event.target.result;
          resolve();
        };
        request.onerror = () => resolve();
      });
    }

    async initStateFileControls() {
      await this.dbReady;
      if (!this.fileSystemAccessSupported) {
        $("level2FileStatus").textContent = "This browser cannot remember a state file. Use Chrome or Edge desktop for Stateless Gen 2.0.";
        this.showStatus("Status: file remembering is not supported in this browser.", "warning");
        return;
      }
      this.stateFileHandle = await this.loadRememberedFileHandle();
      if (this.stateFileHandle) {
        $("level2Reconnect").hidden = false;
        $("level2FileStatus").textContent = "A previous Stateless Gen 2.0 state file is remembered.";
      }
      this.updateUI();
      this.initStandaloneMode();
      this.setLayout(localStorage.getItem(this.layoutStorageKey) || "default", false);
    }

    showStatus(message, type = "info") {
      $("level2Status").textContent = message;
      $("level2Status").dataset.kind = type;
    }

    showResult(message, type = "info") {
      $("level2Result").textContent = message;
      $("level2Result").dataset.kind = type;
    }

    updateUI() {
      $("level2SaveState").disabled = !this.isUnlocked || !this.stateFileHandle;
      $("level2SaveAs").disabled = !this.isUnlocked || !this.fileSystemAccessSupported;
      $("level2Export").disabled = !this.isUnlocked && !localStorage.getItem(this.localStorageKey);
      $("level2OpenState").disabled = !this.fileSystemAccessSupported;
      $("level2AutoRecord").textContent = this.autoRecord ? "Auto-record on" : "Auto-record off";
      $("level2AutoRecord").setAttribute("aria-pressed", String(this.autoRecord));
      $("level2CopyPassword").disabled = !this.generatedPassword;
      $("level2TogglePassword").disabled = !this.generatedPassword;
      $("level2TogglePassword").hidden = $("level2MethodCopyOnly").checked;
      $("level2TogglePassword").textContent = this.generatedVisible ? "Hide password" : "Show password";
      this.updateMapPrivacyControls();
      this.updatePasswordStyleFields();
      this.updateSettingsReveals();
      this.updateGoogleStatus();
      this.updateTrustedDeviceStatus();
    }

    showPanel(panelId) {
      ["level2GeneratorPanel", "level2SettingsPanel"].forEach(id => {
        $(id).hidden = id !== panelId;
      });
      document.querySelectorAll("[data-level2-panel]").forEach(button => {
        button.classList.toggle("active", button.dataset.level2Panel === panelId);
      });
    }

    initStandaloneMode() {
      const params = new URLSearchParams(window.location.search);
      if (params.get("standalone") === "1") document.body.classList.add("level2-standalone");
    }

    setLayout(layout, save = true) {
      const allowed = new Set(["default", "wide", "legend-top", "split"]);
      const next = allowed.has(layout) ? layout : "default";
      document.body.dataset.level2Layout = next;
      if (save) localStorage.setItem(this.layoutStorageKey, next);
      document.querySelectorAll("[data-level2-layout]").forEach(button => {
        button.classList.toggle("active", button.dataset.level2Layout === next);
      });
    }

    masterRequired() {
      return $("level2RequireMaster").checked;
    }

    updateMasterRequirement() {
      const required = this.masterRequired();
      $("level2MasterField").hidden = !required;
      $("level2Master").disabled = !required;
      $("level2ToggleMaster").disabled = !required;
      if (!required) {
        $("level2Master").value = "";
        this.masterVisible = false;
        this.updateMasterVisibility();
      }
      $("level2Master").placeholder = required ? "Never saved" : "Not used in this recipe";
      this.showStatus(required ? "Status: master password is required." : "Status: master password is not required for this recipe.", "info");
    }

    updateMasterVisibility() {
      $("level2Master").type = this.masterVisible ? "text" : "password";
      $("level2ToggleMaster").textContent = this.masterVisible ? "Hide" : "Show";
      $("level2ToggleMaster").setAttribute("aria-pressed", String(this.masterVisible));
      $("level2ToggleMaster").setAttribute("aria-label", this.masterVisible ? "Hide master password" : "Show master password");
      $("level2ToggleMaster").title = this.masterVisible ? "Hide master password" : "Show master password";
    }

    toggleMasterVisibility() {
      if (!this.masterRequired()) return;
      this.masterVisible = !this.masterVisible;
      this.updateMasterVisibility();
    }

    updatePasswordStyleFields() {
      $("level2StrengthField").hidden = $("level2Style").value !== "memorable";
    }

    updateSettingsReveals() {
      $("level2GoogleOptions").hidden = !$("level2MethodGoogle").checked;
      $("level2TrustedOptions").hidden = !$("level2MethodTrusted").checked;
    }

    createTrustedDeviceKey() {
      return this.bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    }

    getTrustedDeviceKey() {
      return localStorage.getItem(this.trustedDeviceStorageKey) || "";
    }

    setTrustedDeviceKey(key) {
      localStorage.setItem(this.trustedDeviceStorageKey, key);
    }

    trustedDeviceBackedUp() {
      return localStorage.getItem(this.trustedDeviceBackedUpKey) === "true";
    }

    setTrustedDeviceBackedUp(backedUp) {
      localStorage.setItem(this.trustedDeviceBackedUpKey, String(backedUp));
    }

    ensureTrustedDeviceKey() {
      let key = this.getTrustedDeviceKey();
      if (!key) {
        key = this.createTrustedDeviceKey();
        this.setTrustedDeviceKey(key);
        this.setTrustedDeviceBackedUp(false);
      }
      return key;
    }

    recoveryKeyFromTrustedKey(key) {
      return `GP-TRUSTED-${key}`;
    }

    trustedKeyFromRecoveryKey(value) {
      const clean = String(value || "").trim();
      const key = clean.startsWith("GP-TRUSTED-") ? clean.slice("GP-TRUSTED-".length) : clean;
      return /^[A-Za-z0-9_-]{32,}$/.test(key) ? key : "";
    }

    updateTrustedDeviceSetting() {
      if ($("level2MethodTrusted").checked) this.ensureTrustedDeviceKey();
      this.updateSettingsReveals();
      this.updateTrustedDeviceStatus();
    }

    updateTrustedDeviceStatus() {
      const enabled = $("level2MethodTrusted").checked;
      $("level2TrustedOptions").hidden = !enabled;
      $("level2TrustedWarning").hidden = !enabled;
      $("level2TrustedStatus").textContent = enabled
        ? `Trusted Device Protection: Enabled - Recovery Key: ${this.trustedDeviceBackedUp() ? "Backed up" : "Not backed up"}`
        : "Trusted Device Protection: Disabled";
    }

    async showTrustedRecoveryKey() {
      if (!$("level2MethodTrusted").checked) return alert("Enable Trusted Device Protection first.");
      const ok = confirm("Anyone with this recovery key and your other password ingredients can recreate passwords that use this Trusted Device Key. Store it safely offline.");
      if (!ok) return;
      const recoveryKey = this.recoveryKeyFromTrustedKey(this.ensureTrustedDeviceKey());
      try { await navigator.clipboard.writeText(recoveryKey); } catch {}
      prompt("Recovery Key. Store it safely offline.", recoveryKey);
      this.setTrustedDeviceBackedUp(true);
      this.updateTrustedDeviceStatus();
    }

    restoreTrustedDevice() {
      const value = prompt("Paste your Recovery Key:");
      if (value === null) return;
      const key = this.trustedKeyFromRecoveryKey(value);
      if (!key) return alert("That Recovery Key does not look valid.");
      this.setTrustedDeviceKey(key);
      this.setTrustedDeviceBackedUp(true);
      $("level2MethodTrusted").checked = true;
      this.updateSettingsReveals();
      this.updateTrustedDeviceStatus();
      alert("Trusted Device restored. Passwords using this Trusted Device Key can now be recreated here.");
    }

    getTrustedDeviceGenerationKey() {
      return $("level2MethodTrusted").checked ? this.ensureTrustedDeviceKey() : "";
    }

    updateGoogleStatus() {
      const enabled = $("level2MethodGoogle").checked;
      $("level2GoogleWarning").hidden = !enabled;
      if (this.googleUser) {
        $("level2GoogleStatus").textContent = enabled
          ? `Google Security Factor: Ready as ${this.googleUser.email || this.googleUser.name || "signed in"}`
          : `Google Sign-In: Signed in as ${this.googleUser.email || this.googleUser.name || "signed in"}`;
        return;
      }
      $("level2GoogleStatus").textContent = enabled
        ? "Google Security Factor: Sign in required before generating"
        : "Google Sign-In: Not signed in";
    }

    loadGoogleIdentityScript() {
      if (window.google?.accounts?.id) return Promise.resolve();
      if (this.googleScriptPromise) return this.googleScriptPromise;
      this.googleScriptPromise = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        script.onload = resolve;
        script.onerror = () => reject(new Error("Could not load Google Identity Services."));
        document.head.appendChild(script);
      });
      return this.googleScriptPromise;
    }

    decodeJwtPayload(token) {
      try {
        const payload = token.split(".")[1] || "";
        const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
        const json = decodeURIComponent(atob(normalized).split("").map(char => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""));
        return JSON.parse(json);
      } catch {
        return null;
      }
    }

    handleGoogleCredential(response) {
      const payload = this.decodeJwtPayload(response.credential || "");
      if (!payload?.sub) {
        alert("Google sign-in response could not be read.");
        return;
      }
      this.googleUser = {
        sub: payload.sub,
        email: payload.email || "",
        name: payload.name || ""
      };
      this.updateGoogleStatus();
    }

    async setupGoogleSignIn() {
      try {
        await this.loadGoogleIdentityScript();
        if (!window.google?.accounts?.id) throw new Error("Google Identity Services did not start.");
        window.google.accounts.id.initialize({
          client_id: this.googleClientId,
          callback: response => this.handleGoogleCredential(response),
          auto_select: false
        });
        const buttonTarget = $("level2GoogleSignInButton");
        buttonTarget.innerHTML = "";
        window.google.accounts.id.renderButton(buttonTarget, {
          theme: "outline",
          size: "large",
          width: buttonTarget.clientWidth || 260
        });
        window.google.accounts.id.prompt();
        this.updateGoogleStatus();
      } catch (error) {
        $("level2GoogleStatus").textContent = `Google Sign-In: ${error.message}`;
      }
    }

    googleSignOut() {
      this.googleUser = null;
      if (window.google?.accounts?.id) window.google.accounts.id.disableAutoSelect();
      $("level2GoogleSignInButton").innerHTML = "";
      this.updateGoogleStatus();
    }

    getGoogleSubjectForGeneration() {
      return $("level2MethodGoogle").checked && this.googleUser?.sub ? this.googleUser.sub : "";
    }

    requireWebAuthn() {
      if (!window.isSecureContext) throw new Error("WebAuthn needs HTTPS or localhost.");
      if (!navigator.credentials || !window.PublicKeyCredential) throw new Error("This browser does not support WebAuthn.");
    }

    rpId() {
      return window.location.hostname || "localhost";
    }

    bytesToBase64(bytes) {
      const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      let binary = "";
      array.forEach(byte => { binary += String.fromCharCode(byte); });
      return btoa(binary);
    }

    base64ToBytes(value) {
      const binary = atob(String(value || ""));
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
      return bytes;
    }

    async sha256Bytes(text) {
      return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    }

    bytesToBase64Url(bytes) {
      let binary = "";
      bytes.forEach(byte => { binary += String.fromCharCode(byte); });
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    async fixedPrfSalt() {
      return this.sha256Bytes("GoblinPass Security Map WebAuthn PRF input v1");
    }

    async hkdfSalt() {
      return this.sha256Bytes("GoblinPass Security Map HKDF salt v1");
    }

    async yubiKeySalt(siteId, accountId, masterPassword) {
      const material = `GoblinPass PRF v1|${siteId.trim().toLowerCase()}|${accountId.trim().toLowerCase()}|${masterPassword}`;
      return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
    }

    getPrfOutput(results) {
      return results?.prf?.results?.first || null;
    }

    async mixYubiKeyPrfOutput(output) {
      const mixKey = await crypto.subtle.importKey(
        "raw",
        output,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const mixed = await crypto.subtle.sign("HMAC", mixKey, new TextEncoder().encode("GoblinPass-YubiKey-Mix-v1"));
      return this.bytesToBase64Url(new Uint8Array(mixed));
    }

    async getYubiKeyFactor(siteId, masterPassword) {
      if (!$("level2MethodYubiKey").checked) return "";
      this.requireWebAuthn();
      const accountId = $("level2Login").value.trim();
      const salt = await this.yubiKeySalt(siteId, accountId, masterPassword);
      this.showStatus("Status: authenticate with your YubiKey/passkey for the password ingredient.", "info");
      try {
        const publicKey = {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: this.rpId(),
          userVerification: "preferred",
          timeout: 60000,
          hints: ["security-key"],
          extensions: {
            prf: { eval: { first: salt } }
          }
        };
        if (this.credentialId?.byteLength) {
          publicKey.allowCredentials = [{
            id: this.credentialId,
            type: "public-key",
            transports: ["usb", "nfc", "ble"]
          }];
        }
        const credential = await navigator.credentials.get({
          publicKey
        });
        const output = this.getPrfOutput(credential.getClientExtensionResults?.());
        if (!output || output.byteLength !== 32) {
          throw new Error("This browser or YubiKey did not return PRF extension data.");
        }
        return this.mixYubiKeyPrfOutput(output);
      } catch (error) {
        const message = error?.name === "NotAllowedError"
          ? "YubiKey prompt was cancelled, timed out, the wrong YubiKey was used, or touch/PIN was not completed."
          : error.message || "YubiKey authentication failed.";
        throw new Error(message);
      }
    }

    async deriveAesKey(prfSecret) {
      const keyMaterial = await crypto.subtle.importKey("raw", prfSecret, "HKDF", false, ["deriveKey"]);
      return crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: await this.hkdfSalt(), info: new TextEncoder().encode("GoblinPass Security Map AES-GCM v1") },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    }

    async saveRememberedFileHandle(handle) {
      if (!this.db) await this.initDatabase();
      if (!this.db) return false;
      return new Promise(resolve => {
        const transaction = this.db.transaction([this.storeName], "readwrite");
        const request = transaction.objectStore(this.storeName).put({ id: this.fileHandleId, fileHandle: handle, updated: Date.now() });
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      });
    }

    async loadRememberedFileHandle() {
      if (!this.db) return null;
      return new Promise(resolve => {
        const transaction = this.db.transaction([this.storeName], "readonly");
        const request = transaction.objectStore(this.storeName).get(this.fileHandleId);
        request.onsuccess = () => resolve(request.result?.fileHandle || null);
        request.onerror = () => resolve(null);
      });
    }

    async ensureFilePermission(handle, mode) {
      const options = { mode };
      if (await handle.queryPermission(options) === "granted") return true;
      if (await handle.requestPermission(options) === "granted") return true;
      throw new Error(`${mode === "readwrite" ? "Write" : "Read"} permission was not granted.`);
    }

    async registerTestState() {
      try {
        this.requireWebAuthn();
        this.showStatus("Status: touch your YubiKey/passkey to create the beta state.", "info");
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "GoblinPass Stateless Gen 2.0 Beta", id: this.rpId() },
            user: { id: new TextEncoder().encode(crypto.randomUUID()), name: "goblinpass-stateless-gen2-beta-user", displayName: "GoblinPass Stateless Gen 2.0 Beta" },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }],
            authenticatorSelection: { authenticatorAttachment: "cross-platform", userVerification: "required" },
            extensions: { prf: { eval: { first: await this.fixedPrfSalt() } } },
            timeout: 60000
          }
        });
        const extensionResults = credential.getClientExtensionResults?.() || {};
        if (!extensionResults.prf?.enabled) throw new Error("PRF not supported by this browser/security-key flow.");
        this.credentialId = new Uint8Array(credential.rawId);
        localStorage.setItem(this.credentialStorageKey, this.bytesToBase64(this.credentialId));
        await this.unlockWithCredential(this.credentialId);
        this.rows = [];
        this.hideMapEntries();
        await this.saveEncryptedLocalRecord();
        this.renderRows();
        this.showStatus("Status: beta Security Map created and unlocked.", "success");
      } catch (error) {
        this.showStatus(`Status: beta setup failed: ${error.message}`, "warning");
      }
    }

    async unlockWithCredential(credentialId) {
      this.requireWebAuthn();
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{ id: credentialId, type: "public-key", transports: ["usb", "nfc", "ble"] }],
          extensions: { prf: { eval: { first: await this.fixedPrfSalt() } } },
          timeout: 60000,
          userVerification: "required"
        }
      });
      const extensionResults = credential.getClientExtensionResults?.() || {};
      const prfSecret = extensionResults.prf?.results?.first;
      if (!prfSecret) throw new Error("PRF not supported or no PRF secret returned.");
      this.cryptoKey = await this.deriveAesKey(prfSecret);
      this.credentialId = credentialId;
      this.isUnlocked = true;
      this.updateUI();
    }

    normalizedRows() {
      return this.rows.map(row => ({
        id: String(row.id || ""),
        site: String(row.site || ""),
        securityMethods: Array.isArray(row.securityMethods) ? row.securityMethods.slice() : [],
        passwordHint: String(row.passwordHint || ""),
        length: Number.parseInt(row.length || 16, 10),
        counter: Number.parseInt(row.counter || 1, 10),
        passwordStyle: row.passwordStyle === "memorable" ? "memorable" : "maximum",
        memorableStrength: ["easy", "standard", "strong"].includes(row.memorableStrength) ? row.memorableStrength : "standard",
        updated: String(row.updated || new Date().toISOString())
      }));
    }

    cleanRows(rows) {
      return rows.map(row => ({
        key: crypto.randomUUID(),
        id: String(row.id || ""),
        site: String(row.site || ""),
        securityMethods: Array.isArray(row.securityMethods) ? row.securityMethods.filter(method => this.icons.some(icon => icon.id === method)) : [],
        passwordHint: String(row.passwordHint || ""),
        length: Number.parseInt(row.length || 16, 10),
        counter: Number.parseInt(row.counter || 1, 10),
        passwordStyle: row.passwordStyle === "memorable" ? "memorable" : "maximum",
        memorableStrength: ["easy", "standard", "strong"].includes(row.memorableStrength) ? row.memorableStrength : "standard",
        updated: String(row.updated || "")
      }));
    }

    async encryptedRecordFromRows() {
      if (!this.cryptoKey || !this.credentialId) throw new Error("Map is locked.");
      const plaintext = { type: this.exportType, version: this.dataVersion, updatedAt: new Date().toISOString(), rows: this.normalizedRows() };
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.cryptoKey, new TextEncoder().encode(JSON.stringify(plaintext)));
      return {
        version: 1,
        type: "goblinpass-state",
        alg: "AES-GCM",
        kdf: "WebAuthn-PRF-HKDF-SHA256",
        credentialId: this.bytesToBase64(this.credentialId),
        iv: this.bytesToBase64(iv),
        data: this.bytesToBase64(new Uint8Array(encrypted))
      };
    }

    async decryptRecord(encryptedRecord) {
      if (!this.cryptoKey) throw new Error("Map is locked.");
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.base64ToBytes(encryptedRecord.iv) }, this.cryptoKey, this.base64ToBytes(encryptedRecord.data));
      const payload = JSON.parse(new TextDecoder().decode(decrypted));
      if (payload.type !== this.exportType || !Array.isArray(payload.rows)) throw new Error("Decrypted data is not a Security Map.");
      return payload;
    }

    exportPayloadFromRecord(encryptedRecord) {
      return { type: this.exportType, name: "GoblinPass State", exportedAt: new Date().toISOString(), encryptedRecord };
    }

    async saveEncryptedLocalRecord() {
      const encryptedRecord = await this.encryptedRecordFromRows();
      localStorage.setItem(this.localStorageKey, JSON.stringify(encryptedRecord));
      return encryptedRecord;
    }

    async applyExportPayload(parsed) {
      if (parsed.type !== this.exportType || !parsed.encryptedRecord) throw new Error("This file is not a GoblinPass State export.");
      const encryptedRecord = parsed.encryptedRecord;
      const credentialId = this.base64ToBytes(encryptedRecord.credentialId);
      this.showStatus("Status: touch the matching YubiKey/passkey to unlock.", "info");
      await this.unlockWithCredential(credentialId);
      const payload = await this.decryptRecord(encryptedRecord);
      this.rows = this.cleanRows(payload.rows);
      this.hideMapEntries();
      localStorage.setItem(this.localStorageKey, JSON.stringify(encryptedRecord));
      localStorage.setItem(this.credentialStorageKey, this.bytesToBase64(credentialId));
      this.renderRows();
      this.showStatus("Status: beta Security Map connected and unlocked.", "success");
    }

    async openStateFile() {
      try {
        const [handle] = await window.showOpenFilePicker({
          multiple: false,
          types: [{ description: "GoblinPass State encrypted JSON", accept: { "application/json": [".json"] } }]
        });
        await this.loadStateFileHandle(handle, true);
      } catch (error) {
        if (error.name === "AbortError") return;
        this.showStatus(`Status: open failed: ${error.message}`, "warning");
      }
    }

    async reconnectStateFile() {
      try {
        if (!this.stateFileHandle) this.stateFileHandle = await this.loadRememberedFileHandle();
        if (!this.stateFileHandle) throw new Error("No remembered Stateless Gen 2.0 file was found.");
        await this.loadStateFileHandle(this.stateFileHandle, false);
      } catch (error) {
        this.showStatus(`Status: reconnect failed: ${error.message}`, "warning");
      }
    }

    async loadStateFileHandle(handle, rememberHandle) {
      await this.ensureFilePermission(handle, "read");
      const file = await handle.getFile();
      const parsed = JSON.parse(await file.text());
      await this.applyExportPayload(parsed);
      this.stateFileHandle = handle;
      if (rememberHandle) await this.saveRememberedFileHandle(handle);
      $("level2Reconnect").hidden = true;
      $("level2FileStatus").textContent = `Connected state file: ${file.name || this.stateFileName}`;
      this.updateUI();
    }

    async writeExportPayloadToHandle(handle, exportPayload) {
      const writable = await handle.createWritable();
      await writable.write(JSON.stringify(exportPayload, null, 2));
      await writable.close();
    }

    async saveToOpenedStateFile() {
      try {
        if (!this.stateFileHandle) throw new Error("Open or reconnect a state file first.");
        await this.ensureFilePermission(this.stateFileHandle, "readwrite");
        const encryptedRecord = await this.saveEncryptedLocalRecord();
        await this.writeExportPayloadToHandle(this.stateFileHandle, this.exportPayloadFromRecord(encryptedRecord));
        $("level2FileStatus").textContent = "Saved to opened Stateless Gen 2.0 state file.";
        this.showStatus("Status: encrypted state saved.", "success");
      } catch (error) {
        this.showStatus(`Status: save failed: ${error.message}`, "warning");
      }
    }

    async saveAsNewStateFile() {
      try {
        const handle = await window.showSaveFilePicker({
          suggestedName: this.stateFileName,
          types: [{ description: "GoblinPass State encrypted JSON", accept: { "application/json": [".json"] } }]
        });
        await this.ensureFilePermission(handle, "readwrite");
        const encryptedRecord = await this.saveEncryptedLocalRecord();
        await this.writeExportPayloadToHandle(handle, this.exportPayloadFromRecord(encryptedRecord));
        this.stateFileHandle = handle;
        await this.saveRememberedFileHandle(handle);
        $("level2Reconnect").hidden = true;
        $("level2FileStatus").textContent = "Saved as new Stateless Gen 2.0 state file.";
        this.showStatus("Status: encrypted state saved as a new file.", "success");
        this.updateUI();
      } catch (error) {
        if (error.name === "AbortError") return;
        this.showStatus(`Status: save as failed: ${error.message}`, "warning");
      }
    }

    async exportState() {
      try {
        let encryptedRecord = localStorage.getItem(this.localStorageKey);
        encryptedRecord = encryptedRecord ? JSON.parse(encryptedRecord) : null;
        if (this.isUnlocked) encryptedRecord = await this.saveEncryptedLocalRecord();
        if (!encryptedRecord) throw new Error("No encrypted Stateless Gen 2.0 state exists yet.");
        const blob = new Blob([JSON.stringify(this.exportPayloadFromRecord(encryptedRecord), null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `goblinpass_stateless_gen2_beta_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        this.showStatus("Status: exported encrypted Stateless Gen 2.0 state.", "success");
      } catch (error) {
        this.showStatus(`Status: export failed: ${error.message}`, "warning");
      }
    }

    selectedMethods() {
      const methods = [];
      if ($("level2MethodGoogle").checked) methods.push("google-factor");
      if ($("level2MethodYubiKey").checked) methods.push("yubikey");
      if (this.masterRequired()) methods.push("master-password");
      if ($("level2MethodTrusted").checked) methods.push("trusted-device-id");
      if ($("level2MethodCopyOnly").checked) methods.push("copy-password-only");
      return Array.from(new Set(methods));
    }

    async generateAndMaybeRecord() {
      try {
        const siteId = $("level2SiteId").value.trim();
        const master = this.masterRequired() ? $("level2Master").value : "";
        const googleSubjectId = this.getGoogleSubjectForGeneration();
        if (!siteId) return alert("Enter an ID / Website ID.");
        if (this.masterRequired() && !master) return alert("Enter a master password, or turn it off in Settings.");
        if ($("level2MethodGoogle").checked && !googleSubjectId) return alert("Sign in with Google before generating passwords, or turn off Google Security Factor in Settings.");
        const options = {
          length: $("level2Length").value,
          counter: $("level2Counter").value,
          selectedKeys: ["lower", "upper", "nums", "symbols"],
          securityKey: "",
          trustedDeviceKey: this.getTrustedDeviceGenerationKey(),
          googleSubjectId,
          yubiKeyFactor: await this.getYubiKeyFactor(siteId, master),
          passwordStyle: $("level2Style").value,
          memorableStrength: $("level2Strength").value
        };
        const password = await window.goblinPassGenerate(siteId, master, options);
        this.generatedPassword = password;
        this.generatedVisible = false;
        $("level2ResultBox").hidden = false;
        try { await navigator.clipboard.writeText(password); } catch {}
        if ($("level2MethodCopyOnly").checked) {
          this.showResult(`Password copied. Hidden by Copy Password Only mode. | Hint: ${password.slice(0, 5)}`, "success");
        } else {
          this.showResult(`Generated and copied: ${this.previewPassword(password)} | Hint: ${password.slice(0, 5)}`, "success");
        }
        this.updateUI();
        if (this.autoRecord) await this.recordGenerated(password, options);
      } catch (error) {
        this.showResult(`Generate failed: ${error.message}`, "warning");
      }
    }

    async recordGenerated(password, options) {
      if (!this.isUnlocked) {
        this.showStatus("Status: generated password was not recorded because the Security Map is locked.", "warning");
        return;
      }
      const id = $("level2SiteId").value.trim().toLowerCase();
      const row = {
        key: crypto.randomUUID(),
        id,
        site: $("level2Site").value.trim(),
        securityMethods: this.selectedMethods(),
        passwordHint: password.slice(0, 5),
        length: Number.parseInt(options.length || 16, 10),
        counter: Number.parseInt(options.counter || 1, 10),
        passwordStyle: options.passwordStyle,
        memorableStrength: options.memorableStrength,
        updated: new Date().toISOString()
      };
      const existing = this.rows.findIndex(item => item.id.toLowerCase() === id);
      if (existing >= 0) {
        const existingKey = this.rows[existing].key;
        this.rows[existing] = { ...row, key: existingKey };
        this.revealedRowKeys.delete(existingKey);
      } else {
        this.rows.unshift(row);
      }
      this.renderRows();
      const encryptedRecord = await this.saveEncryptedLocalRecord();
      if (this.stateFileHandle) {
        try {
          await this.ensureFilePermission(this.stateFileHandle, "readwrite");
          await this.writeExportPayloadToHandle(this.stateFileHandle, this.exportPayloadFromRecord(encryptedRecord));
          $("level2FileStatus").textContent = "Auto-record saved to opened state file.";
          this.showStatus("Status: generated entry recorded and saved to state file.", "success");
        } catch {
          this.showStatus("Status: generated entry recorded locally. Save Now needs file permission.", "warning");
        }
      } else {
        this.showStatus("Status: generated entry recorded locally. Use Save as or Export to keep a file copy.", "success");
      }
      this.updateUI();
    }

    hideMapEntries() {
      this.mapRevealAll = false;
      this.revealedRowKeys.clear();
      this.updateMapPrivacyControls();
    }

    toggleMapRevealAll() {
      this.mapRevealAll = !this.mapRevealAll;
      if (this.mapRevealAll) this.revealedRowKeys.clear();
      this.renderRows();
    }

    toggleRowReveal(rowKey) {
      if (this.revealedRowKeys.has(rowKey)) this.revealedRowKeys.delete(rowKey);
      else this.revealedRowKeys.add(rowKey);
      this.renderRows();
    }

    rowIsRevealed(rowKey) {
      return this.mapRevealAll || this.revealedRowKeys.has(rowKey);
    }

    updateMapPrivacyControls() {
      const hasRows = this.isUnlocked && this.rows.length > 0;
      $("level2ToggleMapReveal").disabled = !hasRows;
      $("level2ToggleMapReveal").textContent = this.mapRevealAll ? "Hide all entries" : "Show all entries";
      $("level2ToggleMapReveal").setAttribute("aria-pressed", String(this.mapRevealAll));
      const visibleCount = this.mapRevealAll ? this.rows.length : this.revealedRowKeys.size;
      $("level2MapPrivacyStatus").textContent = hasRows
        ? `${visibleCount ? `${visibleCount} visible.` : "Map entries hidden."}`
        : "Map entries hidden.";
    }

    updateSiteFilter(value) {
      this.siteFilter = String(value || "").trim().toLowerCase();
      this.currentPage = 1;
      this.renderRows();
    }

    updatePageSize(value) {
      const next = Number.parseInt(value, 10);
      this.pageSize = [10, 25, 50, 100].includes(next) ? next : 25;
      this.currentPage = 1;
      this.renderRows();
    }

    filteredRows() {
      if (!this.siteFilter) return [...this.rows];
      return this.rows.filter(row => String(row.site || "").toLowerCase().includes(this.siteFilter));
    }

    totalPagesFor(rows) {
      return Math.max(1, Math.ceil(rows.length / this.pageSize));
    }

    totalPagesForCount(count) {
      return Math.max(1, Math.ceil(count / this.pageSize));
    }

    pagedRows(rows) {
      const totalPages = this.totalPagesFor(rows);
      this.currentPage = Math.min(Math.max(1, this.currentPage), totalPages);
      const start = (this.currentPage - 1) * this.pageSize;
      return rows.slice(start, start + this.pageSize);
    }

    changePage(direction) {
      const filtered = this.filteredRows();
      const totalPages = this.totalPagesFor(filtered);
      this.currentPage = Math.min(Math.max(1, this.currentPage + direction), totalPages);
      this.renderRows();
    }

    updateFilterControls(filteredCount = 0) {
      const filterInput = $("level2SiteFilter");
      const filterStatus = $("level2FilterStatus");
      const pageStatus = $("level2PageStatus");
      const pageSize = $("level2PageSize");
      const prev = $("level2PrevPage");
      const next = $("level2NextPage");
      const hasRows = this.isUnlocked && this.rows.length > 0;
      if (!hasRows) this.currentPage = 1;
      const totalPages = this.totalPagesForCount(filteredCount);
      filterInput.disabled = !hasRows;
      pageSize.disabled = !hasRows;
      pageSize.value = String(this.pageSize);
      prev.disabled = !hasRows || this.currentPage <= 1 || filteredCount <= this.pageSize;
      next.disabled = !hasRows || this.currentPage >= totalPages || filteredCount <= this.pageSize;
      filterStatus.textContent = hasRows
        ? this.siteFilter
          ? `Showing ${filteredCount} of ${this.rows.length} entries matching site.`
          : `Showing ${filteredCount} of ${this.rows.length} entries.`
        : "No entries to filter.";
      pageStatus.textContent = `Page ${this.currentPage} of ${totalPages}`;
    }

    toggleAutoRecord() {
      this.autoRecord = !this.autoRecord;
      this.updateUI();
      this.showStatus(this.autoRecord ? "Status: auto-record enabled." : "Status: auto-record disabled.", "info");
    }

    previewPassword(password) {
      if (!password) return "";
      if (password.length <= 8) return `${password[0]}****${password.slice(-1)}`;
      return `${password.slice(0, 4)}********${password.slice(-4)}`;
    }

    async copyGeneratedPassword() {
      if (!this.generatedPassword) return;
      try {
        await navigator.clipboard.writeText(this.generatedPassword);
        this.showResult(`Copied: ${this.generatedVisible ? this.generatedPassword : this.previewPassword(this.generatedPassword)} | Hint: ${this.generatedPassword.slice(0, 5)}`, "success");
      } catch {
        this.showResult("Clipboard copy was blocked. Use Show password and copy it manually.", "warning");
      }
    }

    toggleGeneratedPassword() {
      if (!this.generatedPassword) return;
      this.generatedVisible = !this.generatedVisible;
      const visible = this.generatedVisible ? this.generatedPassword : this.previewPassword(this.generatedPassword);
      this.showResult(`Generated and copied: ${visible} | Hint: ${this.generatedPassword.slice(0, 5)}`, "success");
      this.updateUI();
    }

    renderIcon(iconId) {
      const icon = this.icons.find(item => item.id === iconId);
      if (!icon) return null;
      const span = document.createElement("span");
      span.className = "security-map-method-icon";
      span.title = icon.title;
      span.setAttribute("aria-label", icon.title);
      const image = document.createElement("i");
      image.className = icon.className.includes("status-dot") ? icon.className : `security-feature-icon small ${icon.className}`;
      image.setAttribute("aria-hidden", "true");
      span.appendChild(image);
      return span;
    }

    renderLegend() {
      const legend = $("level2IconLegend");
      legend.innerHTML = "";
      this.icons.forEach(icon => {
        const item = document.createElement("span");
        item.className = "security-map-icon-button level2-legend-item";
        item.title = icon.title;
        const rendered = this.renderIcon(icon.id);
        if (rendered) item.appendChild(rendered);
        legend.appendChild(item);
      });
    }

    renderRows() {
      const body = $("level2Rows");
      body.innerHTML = "";
      if (!this.isUnlocked) {
        body.innerHTML = "<tr class=\"security-map-empty-row\"><td colspan=\"9\">Connect or create a beta state to begin.</td></tr>";
        this.updateFilterControls(0);
        this.updateUI();
        return;
      }
      if (!this.rows.length) {
        body.innerHTML = "<tr class=\"security-map-empty-row\"><td colspan=\"9\">No generated entries recorded yet.</td></tr>";
        this.updateFilterControls(0);
        this.updateUI();
        return;
      }
      const filtered = this.filteredRows();
      const rowsToRender = this.pagedRows(filtered);
      this.updateFilterControls(filtered.length);
      if (!rowsToRender.length) {
        body.innerHTML = "<tr class=\"security-map-empty-row\"><td colspan=\"9\">No sites match this filter.</td></tr>";
        this.updateUI();
        return;
      }
      rowsToRender.forEach(row => {
        const revealed = this.rowIsRevealed(row.key);
        const editing = this.editingRowKey === row.key;
        const tableRow = document.createElement("tr");
        tableRow.dataset.rowKey = row.key;
        tableRow.className = "level2-entry-row";
        tableRow.addEventListener("click", event => {
          if (event.target.closest("button, input, label")) return;
          this.loadRowIntoGenerator(row.key);
        });
        const methodCell = document.createElement("td");
        methodCell.className = "security-map-method-cell";
        if (editing) {
          methodCell.appendChild(this.methodEditor(row));
        } else if (revealed) {
          const methodList = document.createElement("div");
          methodList.className = "security-map-method-list";
          (row.securityMethods || []).forEach(iconId => {
            const icon = this.renderIcon(iconId);
            if (icon) methodList.appendChild(icon);
          });
          methodCell.appendChild(methodList);
        } else {
          methodCell.appendChild(this.maskedValue("Hidden"));
        }
        tableRow.appendChild(this.textCell(row.id, revealed));
        tableRow.appendChild(this.textCell(row.site, revealed));
        tableRow.appendChild(methodCell);
        tableRow.appendChild(this.textCell(row.passwordHint || "not saved", revealed));
        tableRow.appendChild(this.textCell(row.length || 16, revealed));
        tableRow.appendChild(this.textCell(row.counter || 1, revealed));
        tableRow.appendChild(this.editCell(row, revealed, editing));
        tableRow.appendChild(this.revealCell(row, revealed));
        tableRow.appendChild(this.deleteCell(row, revealed));
        body.appendChild(tableRow);
      });
      this.updateUI();
    }

    textCell(value, revealed = true) {
      const cell = document.createElement("td");
      if (revealed) cell.textContent = String(value || "");
      else cell.appendChild(this.maskedValue());
      return cell;
    }

    maskedValue(label = "Hidden") {
      const span = document.createElement("span");
      span.className = "level2-masked-value";
      span.textContent = "Hidden";
      span.setAttribute("aria-label", label);
      return span;
    }

    methodEditor(row) {
      const editor = document.createElement("div");
      editor.className = "level2-method-editor";
      const selected = new Set(row.securityMethods || []);
      this.icons.forEach(icon => {
        const label = document.createElement("label");
        label.className = "level2-method-edit-option";
        label.title = icon.title;
        const input = document.createElement("input");
        input.type = "checkbox";
        input.value = icon.id;
        input.checked = selected.has(icon.id);
        const rendered = this.renderIcon(icon.id);
        label.appendChild(input);
        if (rendered) label.appendChild(rendered);
        editor.appendChild(label);
      });
      return editor;
    }

    editCell(row, revealed = false, editing = false) {
      const cell = document.createElement("td");
      cell.className = "level2-edit-cell";
      if (editing) {
        const actions = document.createElement("div");
        actions.className = "level2-edit-actions";
        const saveButton = document.createElement("button");
        saveButton.type = "button";
        saveButton.className = "level2-edit-row";
        saveButton.textContent = "Save";
        saveButton.addEventListener("click", () => this.saveRowMethods(row.key));
        const cancelButton = document.createElement("button");
        cancelButton.type = "button";
        cancelButton.className = "level2-edit-row";
        cancelButton.textContent = "Cancel";
        cancelButton.addEventListener("click", () => {
          this.editingRowKey = null;
          this.renderRows();
        });
        actions.appendChild(saveButton);
        actions.appendChild(cancelButton);
        cell.appendChild(actions);
        return cell;
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = "level2-edit-row";
      button.setAttribute("aria-label", revealed ? `Edit ${row.site || row.id || "entry"}` : "Edit hidden entry");
      button.textContent = "Edit";
      button.addEventListener("click", () => this.editRow(row.key));
      cell.appendChild(button);
      return cell;
    }

    revealCell(row, revealed) {
      const cell = document.createElement("td");
      cell.className = "level2-reveal-cell";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "level2-reveal-row";
      button.setAttribute("aria-pressed", String(revealed));
      button.textContent = revealed ? "Hide" : "Show";
      button.addEventListener("click", () => this.toggleRowReveal(row.key));
      cell.appendChild(button);
      return cell;
    }

    deleteCell(row, revealed = false) {
      const cell = document.createElement("td");
      cell.className = "level2-delete-cell";
      const button = document.createElement("button");
      button.type = "button";
      button.className = "level2-delete-row";
      button.setAttribute("aria-label", revealed ? `Delete ${row.site || row.id || "entry"}` : "Delete hidden entry");
      button.textContent = "X";
      button.addEventListener("click", () => this.deleteRow(row.key));
      cell.appendChild(button);
      return cell;
    }

    editRow(rowKey) {
      const row = this.rows.find(item => item.key === rowKey);
      if (!row) return;
      this.editingRowKey = rowKey;
      this.renderRows();
      this.showStatus("Status: edit the security method icons, then save the row.", "info");
    }

    loadRowIntoGenerator(rowKey) {
      const row = this.rows.find(item => item.key === rowKey);
      if (!row) return;
      const methods = new Set(row.securityMethods || []);
      $("level2SiteId").value = row.id || "";
      $("level2Site").value = row.site || "";
      $("level2Length").value = row.length || 16;
      $("level2Counter").value = row.counter || 1;
      $("level2Style").value = row.passwordStyle === "memorable" ? "memorable" : "maximum";
      $("level2Strength").value = row.memorableStrength || "standard";
      $("level2RequireMaster").checked = methods.has("master-password");
      $("level2MethodGoogle").checked = methods.has("google-factor");
      $("level2MethodYubiKey").checked = methods.has("yubikey");
      $("level2MethodTrusted").checked = methods.has("trusted-device-id");
      $("level2MethodCopyOnly").checked = methods.has("copy-password-only");
      $("level2Master").value = "";
      this.showPanel("level2GeneratorPanel");
      this.updateUI();
      this.showStatus("Status: entry loaded into the generator. Re-enter any private ingredients before generating.", "info");
    }

    async saveRowMethods(rowKey) {
      const row = this.rows.find(item => item.key === rowKey);
      const tableRow = document.querySelector(`[data-row-key="${CSS.escape(rowKey)}"]`);
      if (!row || !tableRow) return;
      row.securityMethods = Array.from(tableRow.querySelectorAll(".level2-method-editor input:checked")).map(input => input.value);
      row.updated = new Date().toISOString();
      this.editingRowKey = null;
      try {
        const encryptedRecord = await this.saveEncryptedLocalRecord();
        if (this.stateFileHandle) {
          await this.ensureFilePermission(this.stateFileHandle, "readwrite");
          await this.writeExportPayloadToHandle(this.stateFileHandle, this.exportPayloadFromRecord(encryptedRecord));
          $("level2FileStatus").textContent = "Edited entry and saved to opened state file.";
        }
        this.showStatus("Status: entry security methods updated.", "success");
      } catch (error) {
        this.showStatus(`Status: entry updated locally, but state file update failed: ${error.message}`, "warning");
      }
      this.renderRows();
    }

    async deleteRow(rowKey) {
      if (!this.isUnlocked) return;
      const row = this.rows.find(item => item.key === rowKey);
      const name = this.rowIsRevealed(rowKey) ? row?.site || row?.id || "this entry" : "this hidden entry";
      if (!confirm(`Delete ${name} from the Security Map?`)) return;
      this.rows = this.rows.filter(item => item.key !== rowKey);
      this.revealedRowKeys.delete(rowKey);
      this.renderRows();
      try {
        const encryptedRecord = await this.saveEncryptedLocalRecord();
        if (this.stateFileHandle) {
          await this.ensureFilePermission(this.stateFileHandle, "readwrite");
          await this.writeExportPayloadToHandle(this.stateFileHandle, this.exportPayloadFromRecord(encryptedRecord));
          $("level2FileStatus").textContent = "Deleted entry and saved to opened state file.";
          this.showStatus("Status: entry deleted and encrypted state updated.", "success");
        } else {
          this.showStatus("Status: entry deleted locally. Use Save as or Export to keep a file copy.", "success");
        }
      } catch (error) {
        this.showStatus(`Status: delete saved locally, but state file update failed: ${error.message}`, "warning");
      }
      this.updateUI();
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    window.level2SecurityMapTest = new Level2SecurityMapTest();
  });
})();
