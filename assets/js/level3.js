(function () {
  "use strict";

  const $ = id => document.getElementById(id);

  class GoblinPassGen3 {
    constructor() {
      this.fileName = "goblinpass-gen3-map.json";
      this.recordType = "goblinpass-gen3-map";
      this.totpStorageKey = "goblinpass_gen3_totp_secrets_v1";
      this.mapRecord = null;
      this.dataKey = null;
      this.rows = [];
      this.fileHandle = null;
      this.pendingTotpSecret = "";
      this.generatedPassword = "";
      this.masterVisible = false;
      this.busy = false;
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
      $("gen3PrepareAuthenticator").addEventListener("click", () => this.prepareAuthenticator());
      $("gen3CopySetupKey").addEventListener("click", () => this.copySetupKey());
      $("gen3ToggleSetupQr").addEventListener("click", () => this.toggleSetupQr());
      $("gen3CreateMap").addEventListener("click", () => this.createMap());
      $("gen3OpenMap").addEventListener("click", () => this.openMap());
      $("gen3SelectSave").addEventListener("click", () => this.selectSaveFile());
      $("gen3SaveNow").addEventListener("click", () => this.saveNow());
      $("gen3Lock").addEventListener("click", () => this.lockMap());
      $("gen3UnlockYubiKey").addEventListener("click", () => this.unlockWithYubiKey());
      $("gen3UnlockAuthenticator").addEventListener("click", () => this.unlockWithAuthenticator());
      $("gen3StoreSetupKey").addEventListener("click", () => this.restoreAuthenticatorSetupKey());
      $("gen3Generate").addEventListener("click", () => this.generate());
      $("gen3CopyPassword").addEventListener("click", () => this.copyPassword());
      $("gen3ToggleMaster").addEventListener("click", () => this.toggleMaster());
      $("gen3UseAuthenticator").addEventListener("change", () => {
        $("gen3AuthenticatorSetup").hidden = !$("gen3UseAuthenticator").checked;
        if (!$("gen3UseAuthenticator").checked) this.hideSetupQr();
      });
      $("gen3SetupKey").addEventListener("input", event => {
        this.pendingTotpSecret = this.normalizeTotpSecret(event.target.value);
        if (!$("gen3SetupQrPanel").hidden) this.drawSetupQr();
      });
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
      $("gen3Setup").hidden = !!this.mapRecord;
      if (!this.mapRecord || unlocked) $("gen3Unlock").hidden = true;
      $("gen3FileStatus").textContent = hasSaveFile
        ? `Auto-save connected: ${this.fileName}`
        : (unlocked ? "Select a save file before generating." : "No save file selected. Generation is locked.");
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

    base32Encode(bytes) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      let bits = 0;
      let value = 0;
      let output = "";
      new Uint8Array(bytes).forEach(byte => {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
          output += alphabet[(value >>> (bits - 5)) & 31];
          bits -= 5;
        }
      });
      if (bits) output += alphabet[(value << (5 - bits)) & 31];
      return output;
    }

    base32Decode(value) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      const clean = String(value || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
      let bits = 0;
      let buffer = 0;
      const output = [];
      for (const char of clean) {
        const index = alphabet.indexOf(char);
        if (index < 0) continue;
        buffer = (buffer << 5) | index;
        bits += 5;
        if (bits >= 8) {
          output.push((buffer >>> (bits - 8)) & 255);
          bits -= 8;
        }
      }
      return new Uint8Array(output);
    }

    normalizeTotpSecret(value) {
      return String(value || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
    }

    async totpCode(secret, timeStep = Math.floor(Date.now() / 30000)) {
      const counter = new Uint8Array(8);
      let value = BigInt(timeStep);
      for (let index = 7; index >= 0; index -= 1) {
        counter[index] = Number(value & 255n);
        value >>= 8n;
      }
      const key = await crypto.subtle.importKey("raw", this.base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
      const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
      const offset = digest[digest.length - 1] & 15;
      const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
      return String(number % 1000000).padStart(6, "0");
    }

    async verifyTotp(secret, code) {
      const clean = String(code || "").replace(/\D/g, "");
      if (clean.length !== 6) return false;
      const step = Math.floor(Date.now() / 30000);
      for (let drift = -1; drift <= 1; drift += 1) {
        if (await this.totpCode(secret, step + drift) === clean) return true;
      }
      return false;
    }

    loadTotpSecrets() {
      try { return JSON.parse(localStorage.getItem(this.totpStorageKey) || "{}"); }
      catch { return {}; }
    }

    saveTotpSecret(id, secret) {
      const secrets = this.loadTotpSecrets();
      secrets[id] = secret;
      localStorage.setItem(this.totpStorageKey, JSON.stringify(secrets));
    }

    async totpSecretId(secret) {
      const digest = await this.sha256Bytes(this.base32Decode(secret));
      return this.bytesToBase64Url(digest.slice(0, 12));
    }

    async deriveTotpWrapKey(secret) {
      const material = await crypto.subtle.importKey("raw", this.base32Decode(secret), "PBKDF2", false, ["deriveKey"]);
      return crypto.subtle.deriveKey({
        name: "PBKDF2",
        hash: "SHA-256",
        salt: await this.sha256Bytes("GoblinPass Gen3 Authenticator Wrap v1"),
        iterations: 210000
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
        id: String(row.id || ""),
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
          user: {
            id: crypto.getRandomValues(new Uint8Array(32)),
            name: "goblinpass-gen3-map",
            displayName: "GoblinPass Gen 3.0 Map"
          },
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
      const wrappingKey = await this.deriveYubiWrapKey(output);
      return { type: "yubikey", credentialId, wrappedKey: await this.wrapDataKey(dataKey, wrappingKey) };
    }

    async prepareAuthenticator() {
      this.pendingTotpSecret = this.base32Encode(crypto.getRandomValues(new Uint8Array(20)));
      $("gen3UseAuthenticator").checked = true;
      $("gen3SetupKey").value = this.pendingTotpSecret.match(/.{1,4}/g).join(" ");
      $("gen3SetupCode").value = "";
      $("gen3AuthenticatorSetup").hidden = false;
      this.setStatus("add the setup key to Google Authenticator, then enter its current code before creating the map.");
    }

    authenticatorUri(secret) {
      return `otpauth://totp/GP3?secret=${secret}&issuer=GP`;
    }

    drawSetupQr() {
      const secret = this.normalizeTotpSecret($("gen3SetupKey").value || this.pendingTotpSecret);
      if (secret.length < 16) {
        this.hideSetupQr();
        this.setStatus("enter or prepare a valid Authenticator setup key before showing its QR code.", "warning");
        return false;
      }
      if (!window.GoblinPassQrV4?.draw) {
        this.setStatus("the local QR renderer did not load.", "warning");
        return false;
      }
      try {
        window.GoblinPassQrV4.draw($("gen3SetupQr"), this.authenticatorUri(secret));
        return true;
      } catch (error) {
        this.hideSetupQr();
        this.setStatus(error?.message || "the Authenticator QR code could not be created.", "warning");
        return false;
      }
    }

    toggleSetupQr() {
      const panel = $("gen3SetupQrPanel");
      if (!panel.hidden) {
        this.hideSetupQr();
        return;
      }
      if (!this.drawSetupQr()) return;
      panel.hidden = false;
      $("gen3ToggleSetupQr").textContent = "Hide QR code";
      this.setStatus("Authenticator QR code ready to scan.", "success");
    }

    hideSetupQr() {
      $("gen3SetupQrPanel").hidden = true;
      $("gen3ToggleSetupQr").textContent = "Show QR code";
    }

    async copySetupKey() {
      const secret = this.normalizeTotpSecret($("gen3SetupKey").value || this.pendingTotpSecret);
      if (!secret) return this.setStatus("enter or prepare an Authenticator setup key first.", "warning");
      try {
        await navigator.clipboard.writeText(secret);
        this.setStatus("Authenticator setup key copied.", "success");
      } catch {
        this.setStatus("The setup key could not be copied. Select it manually.", "warning");
      }
    }

    async createMap() {
      if (this.busy) return;
      const useYubiKey = $("gen3UseYubiKey").checked;
      const useAuthenticator = $("gen3UseAuthenticator").checked;
      const authenticatorSecret = this.normalizeTotpSecret($("gen3SetupKey").value || this.pendingTotpSecret);
      if (!useYubiKey && !useAuthenticator) return this.setStatus("select at least one map unlock method.", "warning");
      if (useAuthenticator && authenticatorSecret.length < 16) return this.setStatus("enter or prepare a valid Authenticator setup key first.", "warning");
      if (useAuthenticator && !(await this.verifyTotp(authenticatorSecret, $("gen3SetupCode").value))) {
        return this.setStatus("the Authenticator code did not match the entered setup key.", "warning");
      }

      this.setBusy(true);
      try {
        const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const unlockMethods = [];
        if (useYubiKey) unlockMethods.push(await this.createYubiMethod(dataKey));
        if (useAuthenticator) {
          const secretId = await this.totpSecretId(authenticatorSecret);
          const wrappingKey = await this.deriveTotpWrapKey(authenticatorSecret);
          unlockMethods.push({ type: "totp", secretId, wrappedKey: await this.wrapDataKey(dataKey, wrappingKey) });
          this.saveTotpSecret(secretId, authenticatorSecret);
        }
        this.dataKey = dataKey;
        this.rows = [];
        this.mapRecord = { type: this.recordType, version: 1, updatedAt: new Date().toISOString(), unlockMethods, payload: await this.encryptRows() };
        this.pendingTotpSecret = "";
        $("gen3SetupKey").value = "";
        $("gen3SetupCode").value = "";
        this.hideSetupQr();
        $("gen3AuthenticatorSetup").hidden = true;
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
      $("gen3Unlock").hidden = false;
      $("gen3YubiUnlock").hidden = !methods.some(method => method.type === "yubikey");
      $("gen3TotpUnlock").hidden = !methods.some(method => method.type === "totp");
      $("gen3Setup").hidden = true;
    }

    async finishUnlock(dataKey, label) {
      const rows = await this.decryptRows(this.mapRecord.payload, dataKey);
      this.dataKey = dataKey;
      this.rows = rows;
      this.generatedPassword = "";
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
        const dataKey = await this.unwrapDataKey(method.wrappedKey, await this.deriveYubiWrapKey(output));
        await this.finishUnlock(dataKey, "YubiKey");
      } catch (error) {
        this.setStatus(error?.name === "NotAllowedError" ? "YubiKey sign-in was cancelled, timed out, or used the wrong key." : error?.message || "YubiKey unlock failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async unlockWithAuthenticator() {
      if (this.busy) return;
      const method = this.mapRecord?.unlockMethods.find(item => item.type === "totp");
      if (!method) return;
      const secret = this.loadTotpSecrets()[method.secretId] || "";
      if (!secret) return this.setStatus("this browser does not have the Authenticator setup key. Restore it below first.", "warning");
      if (!(await this.verifyTotp(secret, $("gen3UnlockCode").value))) return this.setStatus("Authenticator code is incorrect or expired.", "warning");
      this.setBusy(true);
      try {
        const dataKey = await this.unwrapDataKey(method.wrappedKey, await this.deriveTotpWrapKey(secret));
        await this.finishUnlock(dataKey, "Google Authenticator");
        $("gen3UnlockCode").value = "";
      } catch (error) {
        this.setStatus(error?.message || "Authenticator unlock failed.", "warning");
      } finally {
        this.setBusy(false);
      }
    }

    async restoreAuthenticatorSetupKey() {
      const method = this.mapRecord?.unlockMethods.find(item => item.type === "totp");
      if (!method) return;
      const secret = String($("gen3RestoreSetupKey").value || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
      if (secret.length < 16 || await this.totpSecretId(secret) !== method.secretId) {
        return this.setStatus("that setup key does not belong to this map.", "warning");
      }
      this.saveTotpSecret(method.secretId, secret);
      $("gen3RestoreSetupKey").value = "";
      this.setStatus("Authenticator setup key restored. Enter the current 6-digit code to unlock.", "success");
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
        const id = siteId.toLowerCase();
        const row = { id, length: 16, counter: 1, hint: password.slice(0, 5), updated: new Date().toISOString() };
        const existing = this.rows.findIndex(item => item.id.toLowerCase() === id);
        if (existing >= 0) this.rows[existing] = row;
        else this.rows.unshift(row);
        await this.saveMap();
        this.generatedPassword = password;
        try { await navigator.clipboard.writeText(password); } catch {}
        $("gen3ResultBox").hidden = false;
        $("gen3Result").textContent = `Generated, copied and saved. Hint: ${row.hint}`;
        $("gen3Result").dataset.kind = "success";
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
      this.showUnlockMethods();
      this.renderRows();
      this.setStatus("map locked.");
      this.updateUI();
    }

    renderRows() {
      if (!this.dataKey) {
        $("gen3MapRows").innerHTML = '<tr><td colspan="5" class="gen3-empty">Unlock a map to view entries.</td></tr>';
        return;
      }
      if (!this.rows.length) {
        $("gen3MapRows").innerHTML = '<tr><td colspan="5" class="gen3-empty">No generations recorded yet.</td></tr>';
        return;
      }
      $("gen3MapRows").innerHTML = this.rows.map(row => `<tr>
        <td>${this.escapeHtml(row.id)}</td>
        <td>${row.length}</td>
        <td>${row.counter}</td>
        <td>${this.escapeHtml(row.hint)}</td>
        <td>${this.escapeHtml(new Date(row.updated).toLocaleString())}</td>
      </tr>`).join("");
    }

    escapeHtml(value) {
      return String(value || "").replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    window.goblinPassGen3 = new GoblinPassGen3();
  });
})();
