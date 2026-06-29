(function () {
  "use strict";

  const $ = id => document.getElementById(id);

  class GoblinPassGen3 {
    constructor() {
      this.fileName = "goblinpass-gen3-map.json";
      this.recordType = "goblinpass-gen3-map";
      this.googleClientId = "908605927082-sne248f74g829ek1kh1mh11gumjj411m.apps.googleusercontent.com";
      this.googleScriptPromise = null;
      this.googleUser = null;
      this.mapRecord = null;
      this.dataKey = null;
      this.rows = [];
      this.fileHandle = null;
      this.generatedPassword = "";
      this.masterVisible = false;
      this.busy = false;
      this.filter = "";
      this.revealAll = false;
      this.revealedRows = new Set();
      this.fileSystemSupported = "showOpenFilePicker" in window && "showSaveFilePicker" in window;
      this.bindEvents();
      this.updateUI();
      this.renderRows();
      if (!this.fileSystemSupported) {
        this.setStatus("This browser cannot select an auto-save file. Use current Chrome or Edge over HTTPS.", "warning");
      }
    }

    bindEvents() {
      $("navToggle")?.addEventListener("click", () => {
        const open = $("navLinks")?.classList.toggle("open");
        $("navToggle").setAttribute("aria-expanded", String(Boolean(open)));
      });
      $("gen3GoogleSetup").addEventListener("click", () => this.setupGoogleSignIn());
      $("gen3GoogleUnlockSetup").addEventListener("click", () => this.setupGoogleSignIn());
      $("gen3GoogleSignOut").addEventListener("click", () => this.googleSignOut());
      $("gen3CreateMap").addEventListener("click", () => this.createMap());
      $("gen3OpenMap").addEventListener("click", () => this.openMap());
      $("gen3SelectSave").addEventListener("click", () => this.selectSaveFile());
      $("gen3SaveNow").addEventListener("click", () => this.saveNow());
      $("gen3Lock").addEventListener("click", () => this.lockMap());
      $("gen3UnlockYubiKey").addEventListener("click", () => this.unlockWithYubiKey());
      $("gen3Generate").addEventListener("click", () => this.generate());
      $("gen3CopyPassword").addEventListener("click", () => this.copyPassword());
      $("gen3ToggleMaster").addEventListener("click", () => this.toggleMaster());
      $("gen3MapFilter").addEventListener("input", event => {
        this.filter = String(event.target.value || "").trim().toLowerCase();
        this.renderRows();
      });
      $("gen3ToggleRows").addEventListener("click", () => this.toggleAllRows());
      $("gen3MapRows").addEventListener("click", event => this.handleRowAction(event));
      $("gen3UseGoogle").addEventListener("change", () => this.updateGoogleStatus());
    }

    setStatus(message, kind = "info") {
      $("gen3Status").textContent = `Status: ${message}`;
      $("gen3Status").dataset.kind = kind;
    }

    setBusy(busy) {
      this.busy = busy;
      this.updateUI();
    }

    updateUI() {
      const unlocked = !!this.dataKey;
      const hasSaveFile = !!this.fileHandle;
      $("gen3CreateMap").disabled = this.busy || !this.fileSystemSupported || !!this.mapRecord;
      $("gen3OpenMap").disabled = this.busy || !this.fileSystemSupported;
      $("gen3SelectSave").disabled = this.busy || !unlocked || !this.fileSystemSupported;
      $("gen3SaveNow").disabled = this.busy || !unlocked || !hasSaveFile;
      $("gen3Lock").disabled = this.busy || (!unlocked && !this.mapRecord);
      $("gen3Generate").disabled = this.busy || !unlocked || !hasSaveFile;
      $("gen3CopyPassword").disabled = !this.generatedPassword;
      $("gen3MapFilter").disabled = !unlocked;
      $("gen3ToggleRows").disabled = !unlocked || !this.rows.length;
      $("gen3ToggleRows").textContent = this.revealAll ? "Hide all" : "Show all";
      $("gen3Setup").hidden = !!this.mapRecord;
      if (!this.mapRecord || unlocked) $("gen3Unlock").hidden = true;
      $("gen3FileStatus").textContent = hasSaveFile
        ? `Auto-save connected: ${this.fileName}`
        : (unlocked ? "Select a save file before generating." : "No save file selected. Generation is locked.");
      this.updateGoogleStatus();
    }

    requireWebAuthn() {
      if (!window.isSecureContext) throw new Error("YubiKey unlock requires HTTPS or localhost.");
      if (!navigator.credentials?.create || !navigator.credentials?.get || !window.PublicKeyCredential) {
        throw new Error("This browser does not support the WebAuthn features required for YubiKey unlock.");
      }
    }

    rpId() {
      return location.hostname || "localhost";
    }

    bytesToBase64(bytes) {
      let binary = "";
      new Uint8Array(bytes).forEach(byte => { binary += String.fromCharCode(byte); });
      return btoa(binary);
    }

    base64ToBytes(value) {
      const binary = atob(String(value || ""));
      return Uint8Array.from(binary, char => char.charCodeAt(0));
    }

    bytesToBase64Url(bytes) {
      return this.bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    base64UrlToBytes(value) {
      const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
      return this.base64ToBytes(normalized + "===".slice((normalized.length + 3) % 4));
    }

    async sha256Bytes(value) {
      const input = typeof value === "string" ? new TextEncoder().encode(value) : value;
      return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    }

    async deriveGoogleWrapKey(subject, salt) {
      const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(subject), "PBKDF2", false, ["deriveKey"]);
      return crypto.subtle.deriveKey({
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: 240000
      }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }

    async deriveYubiWrapKey(prfOutput) {
      const material = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
      return crypto.subtle.deriveKey({
        name: "HKDF",
        hash: "SHA-256",
        salt: await this.sha256Bytes("GoblinPass Gen3 YubiKey Wrap Salt v1"),
        info: new TextEncoder().encode("GoblinPass Gen3 Map Key v1")
      }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }

    async wrapDataKey(dataKey, wrappingKey) {
      const raw = await crypto.subtle.exportKey("raw", dataKey);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, raw);
      return { iv: this.bytesToBase64(iv), data: this.bytesToBase64(data) };
    }

    async unwrapDataKey(wrapped, wrappingKey) {
      const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.base64ToBytes(wrapped.iv) }, wrappingKey, this.base64ToBytes(wrapped.data));
      return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    async encryptRows() {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(JSON.stringify({ rows: this.rows, updatedAt: new Date().toISOString() }));
      const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, this.dataKey, plaintext);
      return { iv: this.bytesToBase64(iv), data: this.bytesToBase64(data) };
    }

    async decryptRows(payload, dataKey) {
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.base64ToBytes(payload.iv) }, dataKey, this.base64ToBytes(payload.data));
      const parsed = JSON.parse(new TextDecoder().decode(plaintext));
      if (!Array.isArray(parsed.rows)) throw new Error("The decrypted map is invalid.");
      return parsed.rows.map(row => ({
        key: String(row.key || crypto.randomUUID()),
        id: String(row.id || ""),
        site: String(row.site || ""),
        login: String(row.login || ""),
        length: 16,
        counter: 1,
        hint: String(row.hint || ""),
        updated: String(row.updated || "")
      }));
    }

    yubiPrfOutput(results, credentialId) {
      const values = results?.prf?.results;
      return values?.first || values?.[credentialId]?.first || null;
    }

    async createYubiMethod(dataKey) {
      this.requireWebAuthn();
      this.setStatus("register the YubiKey for Gen 3 map unlock.");
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { name: "GoblinPass Gen 3.0 Map", id: this.rpId() },
          user: { id: crypto.getRandomValues(new Uint8Array(32)), name: "goblinpass-gen3-map", displayName: "GoblinPass Gen 3.0 Map" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
          authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            residentKey: "required",
            requireResidentKey: true,
            userVerification: "required"
          },
          timeout: 60000,
          extensions: { prf: {}, hmacCreateSecret: true }
        }
      });
      const credentialId = this.bytesToBase64Url(new Uint8Array(credential.rawId));
      this.setStatus("verify the new YubiKey map credential.");
      const salt = await this.sha256Bytes("GoblinPass Gen3 Map PRF v1");
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rpId: this.rpId(),
          allowCredentials: [{ type: "public-key", id: credential.rawId }],
          userVerification: "required",
          timeout: 60000,
          extensions: { prf: { eval: { first: salt } } }
        }
      });
      const output = this.yubiPrfOutput(assertion.getClientExtensionResults?.() || {}, credentialId);
      if (!output || output.byteLength !== 32) throw new Error("The YubiKey did not return a PRF map-unlock secret.");
      return { type: "yubikey", credentialId, wrappedKey: await this.wrapDataKey(dataKey, await this.deriveYubiWrapKey(output)) };
    }

    async createGoogleMethod(dataKey) {
      if (!this.googleUser?.sub) throw new Error("Sign in with Google before creating the map.");
      const salt = crypto.getRandomValues(new Uint8Array(24));
      const subjectHash = this.bytesToBase64Url(await this.sha256Bytes(`GoblinPass Gen3 Google Subject v1|${this.googleUser.sub}`));
      const wrappingKey = await this.deriveGoogleWrapKey(this.googleUser.sub, salt);
      return {
        type: "google",
        subjectHash,
        salt: this.bytesToBase64(salt),
        wrappedKey: await this.wrapDataKey(dataKey, wrappingKey)
      };
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

    async handleGoogleCredential(response) {
      const payload = this.decodeJwtPayload(response?.credential || "");
      if (!payload?.sub) return this.setStatus("Google Sign-In response could not be read.", "warning");
      this.googleUser = { sub: payload.sub, email: payload.email || "", name: payload.name || "" };
      this.updateGoogleStatus();
      this.setStatus(`signed in with Google as ${this.googleUser.email || this.googleUser.name || "the selected account"}.`, "success");
      if (this.mapRecord && !this.dataKey && this.mapRecord.unlockMethods.some(method => method.type === "google")) {
        await this.unlockWithGoogle();
      }
    }

    renderGoogleButtons() {
      if (!window.google?.accounts?.id) return;
      ["gen3GoogleSetupButton", "gen3GoogleUnlockButton"].forEach(id => {
        const target = $(id);
        if (!target || target.closest("[hidden]")) return;
        target.innerHTML = "";
        window.google.accounts.id.renderButton(target, {
          theme: "outline",
          size: "large",
          width: Math.max(220, Math.min(340, target.clientWidth || 280))
        });
      });
    }

    async setupGoogleSignIn() {
      try {
        await this.loadGoogleIdentityScript();
        window.google.accounts.id.initialize({
          client_id: this.googleClientId,
          callback: response => this.handleGoogleCredential(response),
          auto_select: false
        });
        this.renderGoogleButtons();
        this.setStatus("choose the Google account that should unlock this map.");
      } catch (error) {
        this.setStatus(error?.message || "Google Sign-In could not start.", "warning");
      }
    }

    googleSignOut() {
      this.googleUser = null;
      if (window.google?.accounts?.id) window.google.accounts.id.disableAutoSelect();
      $("gen3GoogleSetupButton").innerHTML = "";
      $("gen3GoogleUnlockButton").innerHTML = "";
      this.updateGoogleStatus();
      this.setStatus("signed out of Google.");
    }

    updateGoogleStatus() {
      const signedIn = !!this.googleUser?.sub;
      $("gen3GoogleSignOut").disabled = this.busy || !signedIn;
      $("gen3GoogleStatus").textContent = signedIn
        ? `Google Sign-In: ${this.googleUser.email || this.googleUser.name || "Signed in"}`
        : "Google Sign-In: Not signed in";
    }

    async createMap() {
      if (this.busy) return;
      const useYubiKey = $("gen3UseYubiKey").checked;
      const useGoogle = $("gen3UseGoogle").checked;
      if (!useYubiKey && !useGoogle) return this.setStatus("select at least one map unlock method.", "warning");
      if (useGoogle && !this.googleUser?.sub) return this.setStatus("sign in with Google before creating the map.", "warning");

      this.setBusy(true);
      try {
        const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const unlockMethods = [];
        if (useYubiKey) unlockMethods.push(await this.createYubiMethod(dataKey));
        if (useGoogle) unlockMethods.push(await this.createGoogleMethod(dataKey));
        this.dataKey = dataKey;
        this.rows = [];
        this.mapRecord = { type: this.recordType, version: 1, updatedAt: new Date().toISOString(), unlockMethods, payload: await this.encryptRows() };
        this.resetRevealState();
        this.renderRows();
        this.setStatus("encrypted map created. Select a save file to enable generation.", "success");
      } catch (error) {
        this.setStatus(error?.message || "map creation failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    validateRecord(record) {
      if (record?.type !== this.recordType || record.version !== 1 || !Array.isArray(record.unlockMethods) || !record.payload) {
        throw new Error("This is not a GoblinPass Gen 3.0 map file.");
      }
      return record;
    }

    async openMap() {
      if (this.busy || !this.fileSystemSupported) return;
      try {
        const [handle] = await window.showOpenFilePicker({
          multiple: false,
          types: [{ description: "GoblinPass Gen 3 encrypted map", accept: { "application/json": [".json"] } }]
        });
        const file = await handle.getFile();
        this.mapRecord = this.validateRecord(JSON.parse(await file.text()));
        this.fileHandle = handle;
        this.fileName = file.name || this.fileName;
        this.dataKey = null;
        this.rows = [];
        this.resetRevealState();
        this.showUnlockMethods();
        this.renderRows();
        this.setStatus("choose a configured method to unlock the map.");
        this.updateUI();
      } catch (error) {
        if (error?.name === "AbortError") return;
        this.setStatus(error?.message || "map opening failed.", "warning");
      }
    }

    showUnlockMethods() {
      const methods = this.mapRecord?.unlockMethods || [];
      const hasYubiKey = methods.some(method => method.type === "yubikey");
      const hasGoogle = methods.some(method => method.type === "google");
      $("gen3Unlock").hidden = false;
      $("gen3YubiUnlock").hidden = !hasYubiKey;
      $("gen3GoogleUnlock").hidden = !hasGoogle;
      $("gen3Setup").hidden = true;
      if (hasGoogle && window.google?.accounts?.id) this.renderGoogleButtons();
      if (!hasYubiKey && !hasGoogle) this.setStatus("this map does not contain a supported Gen 3 unlock method.", "warning");
    }

    async finishUnlock(dataKey, label) {
      this.rows = await this.decryptRows(this.mapRecord.payload, dataKey);
      this.dataKey = dataKey;
      this.generatedPassword = "";
      this.resetRevealState();
      this.renderRows();
      this.setStatus(`map unlocked with ${label}.`, "success");
      this.updateUI();
    }

    async unlockWithYubiKey() {
      if (this.busy) return;
      const method = this.mapRecord?.unlockMethods.find(item => item.type === "yubikey");
      if (!method) return;
      this.setBusy(true);
      try {
        this.requireWebAuthn();
        this.setStatus("sign in with the YubiKey assigned to this map.");
        const salt = await this.sha256Bytes("GoblinPass Gen3 Map PRF v1");
        const credential = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: this.rpId(),
            allowCredentials: [{ type: "public-key", id: this.base64UrlToBytes(method.credentialId) }],
            userVerification: "required",
            timeout: 60000,
            extensions: { prf: { eval: { first: salt } } }
          }
        });
        const output = this.yubiPrfOutput(credential.getClientExtensionResults?.() || {}, method.credentialId);
        if (!output || output.byteLength !== 32) throw new Error("The YubiKey did not return the map-unlock secret.");
        await this.finishUnlock(await this.unwrapDataKey(method.wrappedKey, await this.deriveYubiWrapKey(output)), "YubiKey");
      } catch (error) {
        this.setStatus(error?.name === "NotAllowedError" ? "YubiKey sign-in was cancelled, timed out, or used the wrong key." : error?.message || "YubiKey unlock failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async unlockWithGoogle() {
      if (this.busy || !this.googleUser?.sub) return;
      const method = this.mapRecord?.unlockMethods.find(item => item.type === "google");
      if (!method) return;
      this.setBusy(true);
      try {
        const subjectHash = this.bytesToBase64Url(await this.sha256Bytes(`GoblinPass Gen3 Google Subject v1|${this.googleUser.sub}`));
        if (subjectHash !== method.subjectHash) throw new Error("This Google account is not assigned to this map.");
        const wrappingKey = await this.deriveGoogleWrapKey(this.googleUser.sub, this.base64ToBytes(method.salt));
        await this.finishUnlock(await this.unwrapDataKey(method.wrappedKey, wrappingKey), "Google Sign-In");
      } catch (error) {
        this.setStatus(error?.message || "Google map unlock failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async ensureWritePermission(handle) {
      const options = { mode: "readwrite" };
      if (await handle.queryPermission(options) === "granted") return;
      if (await handle.requestPermission(options) !== "granted") throw new Error("Write permission was not granted.");
    }

    async selectSaveFile() {
      if (!this.dataKey || !this.fileSystemSupported) return;
      const previousHandle = this.fileHandle;
      const previousName = this.fileName;
      try {
        const handle = await window.showSaveFilePicker({
          suggestedName: this.fileName,
          types: [{ description: "GoblinPass Gen 3 encrypted map", accept: { "application/json": [".json"] } }]
        });
        this.fileHandle = handle;
        this.fileName = handle.name || this.fileName;
        await this.saveMap();
        this.setStatus("save file selected. Future generations will update it automatically.", "success");
      } catch (error) {
        this.fileHandle = previousHandle;
        this.fileName = previousName;
        if (error?.name === "AbortError") return;
        this.setStatus(error?.message || "save file selection failed.", "warning");
      } finally {
        this.updateUI();
      }
    }

    async saveMap() {
      if (!this.dataKey || !this.fileHandle || !this.mapRecord) return false;
      await this.ensureWritePermission(this.fileHandle);
      this.mapRecord.payload = await this.encryptRows();
      this.mapRecord.updatedAt = new Date().toISOString();
      const writable = await this.fileHandle.createWritable();
      await writable.write(JSON.stringify(this.mapRecord, null, 2));
      await writable.close();
      $("gen3FileStatus").textContent = `Auto-save connected: ${this.fileName} - last saved ${new Date().toLocaleTimeString()}`;
      return true;
    }

    async saveNow() {
      if (this.busy) return;
      this.setBusy(true);
      try {
        await this.saveMap();
        this.setStatus("encrypted map saved.", "success");
      } catch (error) {
        this.setStatus(error?.message || "map save failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async generate() {
      if (this.busy || !this.dataKey || !this.fileHandle) return;
      const siteId = $("gen3SiteId").value.trim();
      const site = $("gen3Site").value.trim();
      const login = $("gen3Login").value.trim();
      const masterPassword = $("gen3Master").value;
      if (!siteId) return this.setStatus("enter a Website ID.", "warning");
      if (!masterPassword) return this.setStatus("enter the Master Password.", "warning");
      this.setBusy(true);
      const previousRows = this.rows.map(row => ({ ...row }));
      const previousPayload = this.mapRecord.payload;
      const previousUpdatedAt = this.mapRecord.updatedAt;
      try {
        const password = await window.goblinPassGenerate(siteId, masterPassword, {
          length: 16,
          counter: 1,
          selectedKeys: ["lower", "upper", "nums", "symbols"]
        });
        const normalizedId = siteId.toLowerCase();
        const existing = this.rows.findIndex(item => item.id.toLowerCase() === normalizedId);
        const row = {
          key: existing >= 0 ? this.rows[existing].key : crypto.randomUUID(),
          id: normalizedId,
          site,
          login,
          length: 16,
          counter: 1,
          hint: password.slice(0, 5),
          updated: new Date().toISOString()
        };
        if (existing >= 0) this.rows[existing] = row;
        else this.rows.unshift(row);
        await this.saveMap();
        this.generatedPassword = password;
        try { await navigator.clipboard.writeText(password); } catch {}
        $("gen3ResultBox").hidden = false;
        $("gen3Result").textContent = `Generated, copied and saved. Hint: ${row.hint}`;
        $("gen3Result").dataset.kind = "success";
        this.revealedRows.add(row.key);
        this.renderRows();
        this.setStatus("password generated and map file updated.", "success");
      } catch (error) {
        this.rows = previousRows;
        this.mapRecord.payload = previousPayload;
        this.mapRecord.updatedAt = previousUpdatedAt;
        this.renderRows();
        this.setStatus(`generation stopped because the map could not be updated: ${error?.message || error}`, "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async handleRowAction(event) {
      const button = event.target.closest("button[data-row-action]");
      if (!button || !this.dataKey) return;
      const row = this.rows.find(item => item.key === button.dataset.rowKey);
      if (!row) return;
      if (button.dataset.rowAction === "toggle") {
        if (this.revealedRows.has(row.key)) this.revealedRows.delete(row.key);
        else this.revealedRows.add(row.key);
        this.renderRows();
        return;
      }
      if (button.dataset.rowAction !== "delete") return;
      const label = this.revealedRows.has(row.key) || this.revealAll ? row.site || row.id : "this hidden entry";
      if (!confirm(`Delete ${label} from the encrypted map?`)) return;
      const previousRows = this.rows.map(item => ({ ...item }));
      const previousPayload = this.mapRecord.payload;
      const previousUpdatedAt = this.mapRecord.updatedAt;
      this.rows = this.rows.filter(item => item.key !== row.key);
      this.revealedRows.delete(row.key);
      this.renderRows();
      try {
        await this.saveMap();
        this.setStatus("entry deleted and encrypted map updated.", "success");
      } catch (error) {
        this.rows = previousRows;
        this.mapRecord.payload = previousPayload;
        this.mapRecord.updatedAt = previousUpdatedAt;
        this.renderRows();
        this.setStatus(`delete failed: ${error?.message || error}`, "warning");
      }
    }

    toggleAllRows() {
      if (!this.dataKey) return;
      this.revealAll = !this.revealAll;
      if (!this.revealAll) this.revealedRows.clear();
      this.renderRows();
      this.updateUI();
    }

    resetRevealState() {
      this.revealAll = false;
      this.revealedRows.clear();
      this.filter = "";
      if ($("gen3MapFilter")) $("gen3MapFilter").value = "";
    }

    async copyPassword() {
      if (!this.generatedPassword) return;
      try {
        await navigator.clipboard.writeText(this.generatedPassword);
        this.setStatus("generated password copied.", "success");
      } catch {
        this.setStatus("the password could not be copied.", "warning");
      }
    }

    toggleMaster() {
      this.masterVisible = !this.masterVisible;
      $("gen3Master").type = this.masterVisible ? "text" : "password";
      $("gen3ToggleMaster").textContent = this.masterVisible ? "Hide" : "Show";
      $("gen3ToggleMaster").setAttribute("aria-pressed", String(this.masterVisible));
      $("gen3ToggleMaster").setAttribute("aria-label", this.masterVisible ? "Hide master password" : "Show master password");
    }

    lockMap() {
      this.dataKey = null;
      this.rows = [];
      this.generatedPassword = "";
      $("gen3Master").value = "";
      $("gen3ResultBox").hidden = true;
      this.resetRevealState();
      this.showUnlockMethods();
      this.renderRows();
      this.setStatus("map locked.");
      this.updateUI();
    }

    renderRows() {
      if (!this.dataKey) {
        $("gen3MapRows").innerHTML = '<tr><td colspan="8" class="gen3-empty">Unlock a map to view entries.</td></tr>';
        return;
      }
      const filtered = this.rows.filter(row => !this.filter || [row.id, row.site, row.login, row.hint].some(value => String(value).toLowerCase().includes(this.filter)));
      if (!filtered.length) {
        $("gen3MapRows").innerHTML = `<tr><td colspan="8" class="gen3-empty">${this.rows.length ? "No matching entries." : "No generations recorded yet."}</td></tr>`;
        return;
      }
      $("gen3MapRows").innerHTML = filtered.map(row => {
        const revealed = this.revealAll || this.revealedRows.has(row.key);
        const updated = row.updated && !Number.isNaN(Date.parse(row.updated)) ? new Date(row.updated).toLocaleString() : "";
        return `<tr class="${revealed ? "is-revealed" : "is-hidden"}">
          <td>${revealed ? this.escapeHtml(row.id) : '<span class="gen3-masked">Hidden entry</span>'}</td>
          <td>${revealed ? this.escapeHtml(row.site || "-") : '<span class="gen3-masked">Hidden</span>'}</td>
          <td>${revealed ? this.escapeHtml(row.login || "-") : '<span class="gen3-masked">Hidden</span>'}</td>
          <td>${revealed ? row.length : "-"}</td>
          <td>${revealed ? row.counter : "-"}</td>
          <td>${revealed ? this.escapeHtml(row.hint) : '<span class="gen3-masked">Hidden</span>'}</td>
          <td>${revealed ? this.escapeHtml(updated) : '<span class="gen3-masked">Hidden</span>'}</td>
          <td><div class="gen3-row-actions">
            <button type="button" data-row-action="toggle" data-row-key="${this.escapeHtml(row.key)}">${revealed ? "Hide" : "Show"}</button>
            <button type="button" class="danger" data-row-action="delete" data-row-key="${this.escapeHtml(row.key)}">Delete</button>
          </div></td>
        </tr>`;
      }).join("");
    }

    escapeHtml(value) {
      return String(value || "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    window.goblinPassGen3 = new GoblinPassGen3();
  });
})();
