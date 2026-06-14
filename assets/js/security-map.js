(function () {
  "use strict";

  class SecurityMapVault {
    constructor() {
      this.dbName = "GoblinPassSecurityMapDB";
      this.storeName = "encryptedSecurityMap";
      this.recordId = "main";
      this.fileHandleId = "state-file-handle";
      this.localStorageKey = "goblinpass_security_map_encrypted_record";
      this.credentialStorageKey = "goblinpass_security_map_prf_credential";
      this.backupCodesCredentialKey = "goblinpass_backup_codes_yubikey_prf_meta";
      this.exportType = "goblinpass-security-map";
      this.stateFileName = "goblinpass-security-map-state.json";
      this.dataVersion = 1;
      this.db = null;
      this.rows = [];
      this.selectedRowKey = null;
      this.credentialId = null;
      this.cryptoKey = null;
      this.isUnlocked = false;
      this.fileSystemAccessSupported = "showOpenFilePicker" in window && "showSaveFilePicker" in window;
      this.stateFileHandle = null;
      this.hasChosenPath = false;

      this.icons = [
        { id: "google-factor", label: "Google factor", title: "Google factor", className: "icon-google-factor-vector" },
        { id: "yubikey", label: "YubiKey", title: "YubiKey", className: "icon-yubikey-vector" },
        { id: "additional-secret", label: "Additional secret", title: "Additional secret", className: "icon-additional-secret-vector" },
        { id: "trusted-device-id", label: "Trusted device ID", title: "Trusted device ID", className: "icon-trusted-device-vector" },
        { id: "copy-password-only", label: "Copy password only", title: "Copy password only", className: "icon-copy-only-vector" },
        { id: "protected", label: "Protected", title: "Protected", className: "status-dot protected" }
      ];

      this.setupButton = document.getElementById("setupSecurityMapKey");
      this.frontDoor = document.getElementById("securityMapFrontDoor");
      this.setupPanel = document.getElementById("securityMapSetupPanel");
      this.appShell = document.getElementById("securityMapAppShell");
      this.showSetupButton = document.getElementById("showSecurityMapSetup");
      this.startNewButton = document.getElementById("startNewSecurityMap");
      this.backToFrontButton = document.getElementById("backToSecurityMapFront");
      this.frontImportButton = document.getElementById("frontImportSecurityMap");
      this.frontStatus = document.getElementById("securityMapFrontStatus");
      this.unlockButton = document.getElementById("unlockSecurityMap");
      this.saveButton = document.getElementById("saveSecurityMap");
      this.lockButton = document.getElementById("lockSecurityMap");
      this.deleteRowButton = document.getElementById("deleteSecurityMapRow");
      this.exportButton = document.getElementById("exportSecurityMap");
      this.importButton = document.getElementById("importSecurityMap");
      this.fileInput = document.getElementById("securityMapFileInput");
      this.stateFilePanel = document.getElementById("securityMapStateFilePanel");
      this.stateFileStatus = document.getElementById("securityMapStateFileStatus");
      this.openStateFileButton = document.getElementById("openSecurityMapStateFile");
      this.reconnectStateFileButton = document.getElementById("reconnectSecurityMapStateFile");
      this.saveStateFileButton = document.getElementById("saveSecurityMapStateFile");
      this.saveAsStateFileButton = document.getElementById("saveAsSecurityMapStateFile");
      this.status = document.getElementById("securityMapStatus");
      this.lockIndicator = document.getElementById("securityMapLockIndicator");
      this.rowCount = document.getElementById("securityMapRowCount");
      this.tableBody = document.getElementById("securityMapTableBody");
      this.iconPicker = document.getElementById("securityMapIconPicker");

      this.dbReady = this.initDatabase();
      this.renderIconPicker();
      this.bindEvents();
      this.refreshInitialState();
      this.initStateFileControls();
    }

    async initDatabase() {
      return new Promise(resolve => {
        const request = indexedDB.open(this.dbName, 1);
        request.onupgradeneeded = event => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(this.storeName)) {
            db.createObjectStore(this.storeName, { keyPath: "id" });
          }
        };
        request.onsuccess = event => {
          this.db = event.target.result;
          resolve();
        };
        request.onerror = () => resolve();
      });
    }

    bindEvents() {
      this.showSetupButton?.addEventListener("click", () => this.showSetupPanel());
      this.backToFrontButton?.addEventListener("click", () => this.showFrontDoor());
      this.startNewButton?.addEventListener("click", () => this.startNewSecurityMap());
      this.frontImportButton?.addEventListener("click", () => this.fileInput.click());
      this.setupButton.addEventListener("click", () => this.registerYubiKey());
      this.unlockButton.addEventListener("click", () => this.unlockAndLoad());
      this.saveButton.addEventListener("click", () => this.saveEncryptedLocalState());
      this.lockButton.addEventListener("click", () => this.lock());
      this.deleteRowButton.addEventListener("click", () => this.deleteSelectedRow());
      this.exportButton.addEventListener("click", () => this.exportEncryptedJson());
      this.importButton.addEventListener("click", () => this.fileInput.click());
      this.fileInput.addEventListener("change", event => {
        const file = event.target.files?.[0];
        if (file) this.importEncryptedJson(file);
        this.fileInput.value = "";
      });
      if (this.fileSystemAccessSupported) {
        this.openStateFileButton.addEventListener("click", () => this.openStateFile());
        this.reconnectStateFileButton.addEventListener("click", () => this.reconnectStateFile());
        this.saveStateFileButton.addEventListener("click", () => this.saveToOpenedStateFile());
        this.saveAsStateFileButton.addEventListener("click", () => this.saveAsNewStateFile());
      }
    }

    refreshInitialState() {
      this.showFrontDoor();
      const storedCredential = this.getStoredCredentialId();
      if (storedCredential) {
        this.credentialId = storedCredential;
        this.setupButton.textContent = "Replace YubiKey/passkey";
        this.showStatus("Status: locked. YubiKey credential found.", "info");
      } else {
        this.showStatus("Status: locked. Register a PRF-capable YubiKey/passkey or import GoblinPass State.", "info");
      }
      this.renderRows();
      this.updateUI();
    }

    showStatus(message, type = "info") {
      this.status.textContent = message;
      this.status.dataset.kind = type;
      if (this.frontStatus) {
        this.frontStatus.textContent = message;
        this.frontStatus.dataset.kind = type;
      }
    }

    showFrontDoor() {
      this.hasChosenPath = false;
      if (this.frontDoor) this.frontDoor.hidden = false;
      if (this.setupPanel) this.setupPanel.hidden = true;
      if (this.appShell) this.appShell.hidden = true;
    }

    showSetupPanel() {
      if (this.frontDoor) this.frontDoor.hidden = true;
      if (this.setupPanel) this.setupPanel.hidden = false;
      if (this.appShell) this.appShell.hidden = true;
      this.showStatus("Status: review setup steps, then start a new Security Map.", "info");
    }

    showAppShell() {
      this.hasChosenPath = true;
      if (this.frontDoor) this.frontDoor.hidden = true;
      if (this.setupPanel) this.setupPanel.hidden = true;
      if (this.appShell) this.appShell.hidden = false;
    }

    async startNewSecurityMap() {
      this.showAppShell();
      await this.registerYubiKey();
    }

    updateUI() {
      this.lockIndicator.textContent = this.isUnlocked ? "Unlocked" : "Locked";
      this.lockIndicator.className = `lock-indicator ${this.isUnlocked ? "unlocked" : "locked"}`;
      this.saveButton.disabled = !this.isUnlocked;
      this.lockButton.disabled = !this.isUnlocked;
      this.deleteRowButton.disabled = !this.isUnlocked || !this.selectedRowKey;
      if (this.fileSystemAccessSupported) {
        this.saveStateFileButton.disabled = !this.isUnlocked || !this.stateFileHandle;
        this.saveAsStateFileButton.disabled = !this.isUnlocked;
      }
      this.rowCount.textContent = String(this.rows.length);
      this.iconPicker.querySelectorAll("button").forEach(button => {
        button.disabled = !this.isUnlocked;
      });
    }

    async initStateFileControls() {
      if (!this.fileSystemAccessSupported) {
        this.stateFilePanel.hidden = true;
        return;
      }

      this.stateFilePanel.hidden = false;
      await this.dbReady;
      this.stateFileHandle = await this.loadRememberedFileHandle();
      if (this.stateFileHandle) {
        this.stateFileStatus.textContent = "Previous GoblinPass State remembered. Click Reconnect to continue.";
        this.reconnectStateFileButton.hidden = false;
      } else {
        this.stateFileStatus.textContent = "No GoblinPass State opened.";
        this.reconnectStateFileButton.hidden = true;
      }
      this.updateUI();
    }

    async ensureFilePermission(handle, mode) {
      if (!handle) throw new Error("No GoblinPass State is open.");
      const options = { mode };
      if (await handle.queryPermission(options) === "granted") return true;
      if (await handle.requestPermission(options) === "granted") return true;
      throw new Error(`${mode === "readwrite" ? "Write" : "Read"} permission was not granted for the GoblinPass State.`);
    }

    async saveRememberedFileHandle(handle) {
      if (!this.db) await this.initDatabase();
      if (!this.db) return false;
      try {
        return new Promise(resolve => {
          const transaction = this.db.transaction([this.storeName], "readwrite");
          const request = transaction.objectStore(this.storeName).put({
            id: this.fileHandleId,
            fileHandle: handle,
            updated: Date.now()
          });
          request.onsuccess = () => resolve(true);
          request.onerror = () => resolve(false);
        });
      } catch {
        return false;
      }
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

    requireWebAuthn() {
      if (!window.isSecureContext) {
        throw new Error("WebAuthn needs HTTPS or localhost. Use the GitHub Pages version for YubiKey testing.");
      }
      if (!navigator.credentials || !window.PublicKeyCredential) {
        throw new Error("This browser does not support WebAuthn.");
      }
    }

    rpId() {
      return window.location.hostname || "localhost";
    }

    bytesToBase64(bytes) {
      const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      let binary = "";
      array.forEach(byte => {
        binary += String.fromCharCode(byte);
      });
      return btoa(binary);
    }

    base64ToBytes(value) {
      try {
        const binary = atob(String(value || ""));
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
          bytes[index] = binary.charCodeAt(index);
        }
        return bytes;
      } catch {
        throw new Error("Invalid encrypted file encoding.");
      }
    }

    async sha256Bytes(text) {
      return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    }

    async fixedPrfSalt() {
      return this.sha256Bytes("GoblinPass Security Map WebAuthn PRF input v1");
    }

    async hkdfSalt() {
      return this.sha256Bytes("GoblinPass Security Map HKDF salt v1");
    }

    async deriveAesKey(prfSecret) {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        prfSecret,
        "HKDF",
        false,
        ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: await this.hkdfSalt(),
          info: new TextEncoder().encode("GoblinPass Security Map AES-GCM v1")
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    }

    getStoredCredentialId() {
      try {
        const direct = localStorage.getItem(this.credentialStorageKey);
        if (direct) return this.base64ToBytes(direct);

        const backupCodesMeta = localStorage.getItem(this.backupCodesCredentialKey);
        if (backupCodesMeta) {
          const parsed = JSON.parse(backupCodesMeta);
          if (Array.isArray(parsed.credentialId)) return new Uint8Array(parsed.credentialId);
        }
      } catch {
        return null;
      }
      return null;
    }

    storeCredentialId(credentialId) {
      this.credentialId = credentialId;
      localStorage.setItem(this.credentialStorageKey, this.bytesToBase64(credentialId));
      this.setupButton.textContent = "Replace YubiKey/passkey";
    }

    async registerYubiKey() {
      try {
        this.requireWebAuthn();
        if (this.getStoredCredentialId()) {
          const replace = confirm("Replace the saved Security Map YubiKey/passkey credential for this browser?");
          if (!replace) return;
        }

        this.showAppShell();
        this.showStatus("Status: touch your YubiKey/passkey to register PRF encryption.", "info");
        const credential = await navigator.credentials.create({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: { name: "GoblinPass Security Map", id: this.rpId() },
            user: {
              id: new TextEncoder().encode(crypto.randomUUID()),
              name: "goblinpass-security-map-local-user",
              displayName: "GoblinPass Security Map"
            },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }],
            authenticatorSelection: {
              authenticatorAttachment: "cross-platform",
              userVerification: "required"
            },
            extensions: {
              prf: {
                eval: { first: await this.fixedPrfSalt() }
              }
            },
            timeout: 60000
          }
        });

        const extensionResults = credential.getClientExtensionResults?.() || {};
        if (!extensionResults.prf?.enabled) {
          throw new Error("PRF not supported by this browser/security-key flow.");
        }

        this.storeCredentialId(new Uint8Array(credential.rawId));
        await this.unlockWithCredential(this.credentialId);
        this.rows = [];
        this.selectedRowKey = null;
        this.renderRows();
        this.showStatus("Status: unlocked. YubiKey/passkey PRF credential registered.", "success");
      } catch (error) {
        this.showStatus(`Status: setup failed: ${error.message}`, "warning");
      }
    }

    async unlockWithCredential(credentialId) {
      this.requireWebAuthn();
      if (!credentialId || !credentialId.length) {
        throw new Error("No passkey available. Register a YubiKey/passkey or import GoblinPass State.");
      }

      let credential;
      try {
        credential = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{
              id: credentialId,
              type: "public-key",
              transports: ["usb", "nfc", "ble"]
            }],
            extensions: {
              prf: {
                eval: { first: await this.fixedPrfSalt() }
              }
            },
            timeout: 60000,
            userVerification: "required"
          }
        });
      } catch (error) {
        if (error.name === "NotAllowedError") {
          throw new Error("No matching passkey was used. Check that this is the right YubiKey/passkey and try again.");
        }
        throw new Error(error.message || "YubiKey authentication failed.");
      }

      const extensionResults = credential.getClientExtensionResults?.() || {};
      const prfSecret = extensionResults.prf?.results?.first;
      if (!prfSecret) {
        throw new Error("PRF not supported or no PRF secret returned.");
      }

      this.cryptoKey = await this.deriveAesKey(prfSecret);
      this.credentialId = credentialId;
      this.isUnlocked = true;
      this.updateUI();
    }

    async encryptedRecordFromRows() {
      if (!this.cryptoKey || !this.credentialId) throw new Error("Map is locked.");
      const plaintext = {
        type: this.exportType,
        version: this.dataVersion,
        updatedAt: new Date().toISOString(),
        rows: this.normalizedRows()
      };
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        this.cryptoKey,
        new TextEncoder().encode(JSON.stringify(plaintext))
      );
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
      if (!encryptedRecord || encryptedRecord.alg !== "AES-GCM" || encryptedRecord.kdf !== "WebAuthn-PRF-HKDF-SHA256") {
        throw new Error("Unsupported encrypted Security Map format.");
      }

      try {
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: this.base64ToBytes(encryptedRecord.iv) },
          this.cryptoKey,
          this.base64ToBytes(encryptedRecord.data)
        );
        const payload = JSON.parse(new TextDecoder().decode(decrypted));
        if (payload.type !== this.exportType || !Array.isArray(payload.rows)) {
          throw new Error("Decrypted data is not a Security Map.");
        }
        return payload;
      } catch (error) {
        if (error.message && error.message.includes("Security Map")) throw error;
        throw new Error("Decrypt failed. This may be the wrong YubiKey or a damaged file.");
      }
    }

    async saveEncryptedLocalState() {
      if (!this.isUnlocked) {
        this.showStatus("Status: locked. Unlock with YubiKey/passkey before saving.", "warning");
        return;
      }
      try {
        this.captureRowsFromDom();
        const encryptedRecord = await this.encryptedRecordFromRows();
        await this.saveEncryptedRecord(encryptedRecord);
        this.showStatus("Status: saved encrypted local state.", "success");
      } catch (error) {
        this.showStatus(`Status: save failed: ${error.message}`, "warning");
      }
    }

    async saveEncryptedRecord(encryptedRecord) {
      localStorage.setItem(this.localStorageKey, JSON.stringify(encryptedRecord));
      if (!this.db) await this.initDatabase();
      if (!this.db) return;
      await new Promise(resolve => {
        const transaction = this.db.transaction([this.storeName], "readwrite");
        const request = transaction.objectStore(this.storeName).put({
          id: this.recordId,
          encryptedRecord,
          updated: Date.now()
        });
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
      });
    }

    async loadEncryptedRecord() {
      if (this.db) {
        const indexed = await new Promise(resolve => {
          const transaction = this.db.transaction([this.storeName], "readonly");
          const request = transaction.objectStore(this.storeName).get(this.recordId);
          request.onsuccess = () => resolve(request.result?.encryptedRecord || null);
          request.onerror = () => resolve(null);
        });
        if (indexed) return indexed;
      }
      const stored = localStorage.getItem(this.localStorageKey);
      return stored ? JSON.parse(stored) : null;
    }

    exportPayloadFromRecord(encryptedRecord) {
      return {
        type: this.exportType,
        name: "GoblinPass State",
        exportedAt: new Date().toISOString(),
        encryptedRecord
      };
    }

    async encryptedExportPayloadFromCurrentRows() {
      if (!this.isUnlocked) throw new Error("Unlock the map before saving GoblinPass State.");
      this.captureRowsFromDom();
      const encryptedRecord = await this.encryptedRecordFromRows();
      return this.exportPayloadFromRecord(encryptedRecord);
    }

    async applyEncryptedExportPayload(parsed, saveLocalRecord = true) {
      if (parsed.type !== this.exportType || !parsed.encryptedRecord) {
        throw new Error("This file is not a GoblinPass State export.");
      }
      const encryptedRecord = parsed.encryptedRecord;
      if (!encryptedRecord.credentialId) {
        throw new Error("GoblinPass State metadata does not include a credential ID.");
      }
      const credentialId = this.base64ToBytes(encryptedRecord.credentialId);
      this.showAppShell();
      this.showStatus("Encrypted state loaded. Touch your matching YubiKey/passkey to unlock.", "info");
      await this.unlockWithCredential(credentialId);
      const payload = await this.decryptRecord(encryptedRecord);
      this.rows = this.cleanRows(payload.rows);
      this.selectedRowKey = this.rows[0]?.key || null;
      if (saveLocalRecord) await this.saveEncryptedRecord(encryptedRecord);
      this.storeCredentialId(credentialId);
      this.renderRows();
      return encryptedRecord;
    }

    async unlockAndLoad() {
      try {
        this.showAppShell();
        const encryptedRecord = await this.loadEncryptedRecord();
        const credentialId = encryptedRecord?.credentialId
          ? this.base64ToBytes(encryptedRecord.credentialId)
          : this.getStoredCredentialId();
        if (!credentialId) {
          this.showStatus("Status: no passkey available. Register a YubiKey/passkey or import GoblinPass State.", "warning");
          return;
        }

        this.showStatus("Status: touch the matching YubiKey/passkey to unlock.", "info");
        await this.unlockWithCredential(credentialId);
        this.storeCredentialId(credentialId);

        if (encryptedRecord) {
          const payload = await this.decryptRecord(encryptedRecord);
          this.rows = this.cleanRows(payload.rows);
          this.showStatus("Security Map unlocked. Your encrypted state has been loaded locally.", "success");
        } else {
          this.rows = [];
          this.showStatus("Status: unlocked. Add rows to begin.", "success");
        }
        this.selectedRowKey = this.rows[0]?.key || null;
        this.renderRows();
      } catch (error) {
        this.lock();
        this.showStatus("Could not unlock this state. Use the same YubiKey/passkey that created it.", "warning");
      }
    }

    async exportEncryptedJson() {
      try {
        let encryptedRecord = await this.loadEncryptedRecord();
        if (this.isUnlocked) {
          this.captureRowsFromDom();
          encryptedRecord = await this.encryptedRecordFromRows();
        }
        if (!encryptedRecord) {
          this.showStatus("Status: no GoblinPass State to export yet.", "warning");
          return;
        }
        const exportPayload = this.exportPayloadFromRecord(encryptedRecord);
        const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `goblinpass_state_${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        this.showStatus("Status: exported GoblinPass State.", "success");
      } catch (error) {
        this.showStatus(`Status: export failed: ${error.message}`, "warning");
      }
    }

    async importEncryptedJson(file) {
      try {
        const parsed = JSON.parse(await file.text());
        await this.applyEncryptedExportPayload(parsed, true);
        this.showStatus("Security Map unlocked. Your encrypted state has been loaded locally.", "success");
      } catch (error) {
        this.lock();
        this.showStatus("Could not unlock this state. Use the same YubiKey/passkey that created it.", "warning");
      }
    }

    async openStateFile() {
      try {
        const [handle] = await window.showOpenFilePicker({
          multiple: false,
          types: [{
            description: "GoblinPass State encrypted JSON",
            accept: { "application/json": [".json"] }
          }]
        });
        await this.loadStateFileHandle(handle, true);
      } catch (error) {
        if (error.name === "AbortError") return;
        this.showStatus(`Status: open GoblinPass State failed: ${error.message}`, "warning");
      }
    }

    async reconnectStateFile() {
      try {
        if (!this.stateFileHandle) this.stateFileHandle = await this.loadRememberedFileHandle();
        if (!this.stateFileHandle) throw new Error("No remembered GoblinPass State handle was found.");
        await this.loadStateFileHandle(this.stateFileHandle, false);
      } catch (error) {
        this.showStatus(`Status: reconnect failed: ${error.message}`, "warning");
      }
    }

    async loadStateFileHandle(handle, rememberHandle) {
      await this.ensureFilePermission(handle, "read");
      const file = await handle.getFile();
      const parsed = JSON.parse(await file.text());
      await this.applyEncryptedExportPayload(parsed, true);
      this.stateFileHandle = handle;
      if (rememberHandle) await this.saveRememberedFileHandle(handle);
      this.stateFileStatus.textContent = `GoblinPass State loaded: ${file.name || this.stateFileName}`;
      this.reconnectStateFileButton.hidden = true;
      this.updateUI();
      this.showStatus("Security Map unlocked. Your encrypted state has been loaded locally.", "success");
    }

    async saveToOpenedStateFile() {
      try {
        if (!this.stateFileHandle) throw new Error("Open or reconnect a GoblinPass State first.");
        await this.ensureFilePermission(this.stateFileHandle, "readwrite");
        const exportPayload = await this.encryptedExportPayloadFromCurrentRows();
        await this.writeExportPayloadToHandle(this.stateFileHandle, exportPayload);
        await this.saveEncryptedRecord(exportPayload.encryptedRecord);
        this.stateFileStatus.textContent = "Saved to opened GoblinPass State.";
        this.showStatus("Status: saved encrypted GoblinPass State.", "success");
      } catch (error) {
        this.showStatus(`Status: GoblinPass State save failed: ${error.message}`, "warning");
      }
    }

    async saveAsNewStateFile() {
      try {
        const handle = await window.showSaveFilePicker({
          suggestedName: this.stateFileName,
          types: [{
            description: "GoblinPass State encrypted JSON",
            accept: { "application/json": [".json"] }
          }]
        });
        await this.ensureFilePermission(handle, "readwrite");
        const exportPayload = await this.encryptedExportPayloadFromCurrentRows();
        await this.writeExportPayloadToHandle(handle, exportPayload);
        await this.saveEncryptedRecord(exportPayload.encryptedRecord);
        this.stateFileHandle = handle;
        await this.saveRememberedFileHandle(handle);
        this.stateFileStatus.textContent = "Saved as new GoblinPass State.";
        this.reconnectStateFileButton.hidden = true;
        this.updateUI();
        this.showStatus("Status: saved as new GoblinPass State.", "success");
      } catch (error) {
        if (error.name === "AbortError") return;
        this.showStatus(`Status: save as failed: ${error.message}`, "warning");
      }
    }

    async writeExportPayloadToHandle(handle, exportPayload) {
      const writable = await handle.createWritable();
      await writable.write(JSON.stringify(exportPayload, null, 2));
      await writable.close();
    }

    addRow(afterRowKey = null) {
      if (!this.isUnlocked) return;
      this.captureRowsFromDom();
      const row = {
        key: crypto.randomUUID(),
        id: "",
        site: "",
        securityMethods: []
      };
      if (afterRowKey) {
        const index = this.rows.findIndex(item => item.key === afterRowKey);
        this.rows.splice(index >= 0 ? index + 1 : this.rows.length, 0, row);
      } else {
        this.rows.push(row);
      }
      this.selectedRowKey = row.key;
      this.renderRows();
      this.showStatus("Status: row added.", "info");
    }

    deleteSelectedRow() {
      if (!this.isUnlocked || !this.selectedRowKey) return;
      const selected = this.rows.find(row => row.key === this.selectedRowKey);
      const name = selected?.site || selected?.id || "selected row";
      const ok = confirm(`Delete ${name}? This removes it from the decrypted table view. Save to persist the change.`);
      if (!ok) return;
      this.rows = this.rows.filter(row => row.key !== this.selectedRowKey);
      this.selectedRowKey = this.rows[0]?.key || null;
      this.renderRows();
      this.showStatus("Status: selected row deleted. Save to persist.", "warning");
    }

    insertIcon(iconId) {
      if (!this.isUnlocked) return;
      if (!this.selectedRowKey && this.rows.length) this.selectedRowKey = this.rows[0].key;
      const row = this.rows.find(item => item.key === this.selectedRowKey);
      if (!row) {
        this.showStatus("Status: select a row before inserting icons.", "warning");
        return;
      }
      this.captureRowsFromDom();
      const current = new Set(row.securityMethods || []);
      current.add(iconId);
      row.securityMethods = Array.from(current);
      this.renderRows();
      this.showStatus("Status: icon inserted into selected row.", "success");
    }

    selectRow(rowKey) {
      this.selectedRowKey = rowKey;
      this.tableBody.querySelectorAll("tr[data-row-key]").forEach(row => {
        const selected = row.dataset.rowKey === rowKey;
        row.classList.toggle("is-selected", selected);
        const radio = row.querySelector("input[type='radio']");
        if (radio) radio.checked = selected;
      });
      this.updateUI();
    }

    removeIcon(rowKey, iconId) {
      if (!this.isUnlocked) return;
      this.captureRowsFromDom();
      const row = this.rows.find(item => item.key === rowKey);
      if (!row) return;
      row.securityMethods = row.securityMethods.filter(item => item !== iconId);
      this.renderRows();
      this.showStatus("Status: icon removed. Save to persist.", "info");
    }

    captureRowsFromDom() {
      if (!this.isUnlocked) return;
      this.tableBody.querySelectorAll("tr[data-row-key]").forEach(tableRow => {
        const row = this.rows.find(item => item.key === tableRow.dataset.rowKey);
        if (!row) return;
        row.id = tableRow.querySelector("[data-field='id']")?.textContent.trim() || "";
        row.site = tableRow.querySelector("[data-field='site']")?.textContent.trim() || "";
      });
    }

    cleanRows(rows) {
      return rows.map(row => ({
        key: crypto.randomUUID(),
        id: String(row.id || ""),
        site: String(row.site || ""),
        securityMethods: Array.isArray(row.securityMethods)
          ? row.securityMethods.filter(method => this.icons.some(icon => icon.id === method))
          : []
      }));
    }

    normalizedRows() {
      return this.rows.map(row => ({
        id: String(row.id || ""),
        site: String(row.site || ""),
        securityMethods: Array.isArray(row.securityMethods) ? row.securityMethods.slice() : []
      }));
    }

    renderIcon(iconId, extraClass = "") {
      const icon = this.icons.find(item => item.id === iconId);
      if (!icon) return null;
      const span = document.createElement("span");
      span.className = `security-map-method-icon ${extraClass}`.trim();
      span.title = icon.title;
      span.setAttribute("aria-label", icon.title);
      const image = document.createElement("i");
      image.className = icon.className.includes("status-dot")
        ? icon.className
        : `security-feature-icon small ${icon.className}`;
      image.setAttribute("aria-hidden", "true");
      span.appendChild(image);
      return span;
    }

    renderIconPicker() {
      this.iconPicker.innerHTML = "";
      this.icons.forEach(icon => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "security-map-icon-button";
        button.title = `Insert ${icon.label}`;
        button.setAttribute("aria-label", `Insert ${icon.label}`);
        button.dataset.iconId = icon.id;
        const rendered = this.renderIcon(icon.id);
        if (rendered) button.appendChild(rendered);
        button.addEventListener("click", () => this.insertIcon(icon.id));
        this.iconPicker.appendChild(button);
      });
    }

    renderRows() {
      this.tableBody.innerHTML = "";
      if (!this.isUnlocked) {
        const row = document.createElement("tr");
        row.className = "security-map-empty-row";
        row.innerHTML = "<td colspan=\"5\">Locked. Unlock or import an encrypted map to edit rows.</td>";
        this.tableBody.appendChild(row);
        this.updateUI();
        return;
      }
      if (!this.rows.length) {
        const row = document.createElement("tr");
        row.className = "security-map-empty-row";
        const cell = document.createElement("td");
        cell.colSpan = 5;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "security-map-row-add";
        button.textContent = "Add row";
        button.addEventListener("click", () => this.addRow());
        cell.appendChild(button);
        row.appendChild(cell);
        this.tableBody.appendChild(row);
        this.updateUI();
        return;
      }

      this.rows.forEach(row => {
        const tableRow = document.createElement("tr");
        tableRow.dataset.rowKey = row.key;
        if (row.key === this.selectedRowKey) tableRow.classList.add("is-selected");

        const selectCell = document.createElement("td");
        const radio = document.createElement("input");
        radio.type = "radio";
        radio.name = "security-map-selected-row";
        radio.checked = row.key === this.selectedRowKey;
        radio.setAttribute("aria-label", `Select row ${row.id || row.site || ""}`.trim());
        radio.addEventListener("change", () => {
          this.captureRowsFromDom();
          this.selectRow(row.key);
        });
        selectCell.appendChild(radio);

        const idCell = document.createElement("td");
        idCell.contentEditable = "true";
        idCell.dataset.field = "id";
        idCell.textContent = row.id;
        idCell.addEventListener("focus", () => {
          this.selectRow(row.key);
        });

        const siteCell = document.createElement("td");
        siteCell.contentEditable = "true";
        siteCell.dataset.field = "site";
        siteCell.textContent = row.site;
        siteCell.addEventListener("focus", () => {
          this.selectRow(row.key);
        });

        const methodCell = document.createElement("td");
        methodCell.className = "security-map-method-cell";
        methodCell.tabIndex = 0;
        const methodList = document.createElement("div");
        methodList.className = "security-map-method-list";
        methodCell.addEventListener("focus", () => {
          this.captureRowsFromDom();
          this.selectRow(row.key);
        });
        (row.securityMethods || []).forEach(iconId => {
          const chip = this.renderIcon(iconId, "is-removable");
          if (!chip) return;
          chip.title = `${chip.title} - click to remove`;
          chip.addEventListener("click", () => this.removeIcon(row.key, iconId));
          methodList.appendChild(chip);
        });
        if (!row.securityMethods?.length) {
          const empty = document.createElement("span");
          empty.className = "security-map-method-empty";
          empty.textContent = "Select row and insert icons";
          methodList.appendChild(empty);
        }
        methodCell.appendChild(methodList);

        const addCell = document.createElement("td");
        addCell.className = "security-map-row-add-cell";
        const addButton = document.createElement("button");
        addButton.type = "button";
        addButton.className = "security-map-row-add";
        addButton.textContent = "+";
        addButton.title = "Add row below";
        addButton.setAttribute("aria-label", "Add row below");
        addButton.addEventListener("click", event => {
          event.stopPropagation();
          this.addRow(row.key);
        });
        addCell.appendChild(addButton);

        tableRow.append(selectCell, idCell, siteCell, methodCell, addCell);
        tableRow.addEventListener("click", event => {
          if (event.target.closest(".security-map-method-icon")) return;
          if (this.selectedRowKey !== row.key) {
            this.captureRowsFromDom();
            this.selectRow(row.key);
          }
        });
        this.tableBody.appendChild(tableRow);
      });
      this.updateUI();
    }

    lock() {
      this.rows = [];
      this.selectedRowKey = null;
      this.cryptoKey = null;
      this.isUnlocked = false;
      this.renderRows();
      this.showStatus("Status: locked. Decrypted table cleared from view.", "warning");
    }
  }

  if (document.getElementById("securityMapTableBody")) {
    new SecurityMapVault();
  }
})();
