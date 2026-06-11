(function () {
  "use strict";

  class YubiKeyBackupCodesVault {
    constructor() {
      this.encryptionKey = null;
      this.credentialMeta = null;
      this.isUnlocked = false;
      this.dbName = "GoblinPassBackupCodesDB";
      this.storeName = "encryptedBackupCodes";
      this.db = null;
      this.credentialStorageKey = "goblinpass_backup_codes_yubikey_prf_meta";
      this.legacyCredentialStorageKey = "goblinpass_backup_codes_yubikey_credential_id";
      this.localStorageKey = "goblinpass_backup_codes_encrypted_backup";
      this.prfLabel = "GoblinPass Backup Codes PRF vault";

      this.status = document.getElementById("status");
      this.setupButton = document.getElementById("setupBtn");
      this.unlockButton = document.getElementById("unlockBtn");
      this.saveButton = document.getElementById("saveBtn");
      this.lockButton = document.getElementById("lockBtn");
      this.clearButton = document.getElementById("clearBtn");
      this.exportButton = document.getElementById("exportBtn");
      this.importButton = document.getElementById("importBtn");
      this.purgeButton = document.getElementById("purgeBtn");
      this.fileInput = document.getElementById("fileInput");
      this.noteContent = document.getElementById("noteContent");
      this.lockIndicator = document.getElementById("lockIndicator");
      this.lastSaved = document.getElementById("lastSaved");

      this.initDatabase();
      this.bindEvents();
      this.refreshInitialState();
    }

    async initDatabase() {
      return new Promise(resolve => {
        const request = indexedDB.open(this.dbName, 2);

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
      this.setupButton.addEventListener("click", () => this.setupYubiKey());
      this.unlockButton.addEventListener("click", () => this.unlockAndLoad());
      this.saveButton.addEventListener("click", () => this.saveBackupCodes());
      this.lockButton.addEventListener("click", () => this.lock());
      this.clearButton.addEventListener("click", () => {
        this.noteContent.value = "";
      });
      this.exportButton.addEventListener("click", () => this.exportBackup());
      this.importButton.addEventListener("click", () => this.fileInput.click());
      this.fileInput.addEventListener("change", event => {
        const file = event.target.files?.[0];
        if (file) this.importBackup(file);
        this.fileInput.value = "";
      });
      this.purgeButton.addEventListener("click", () => this.purgeEntries());
    }

    refreshInitialState() {
      if (this.loadLocalCredentialMeta()) {
        this.setupButton.textContent = "Replace YubiKey";
        this.showStatus("Status: YubiKey PRF vault is registered. Sign in to show or save backup codes.", "success");
      } else {
        this.showStatus("Status: ready. Register a PRF-capable YubiKey first.", "info");
      }
      this.updateUI();
    }

    showStatus(message, type = "info") {
      this.status.textContent = message;
      this.status.dataset.kind = type;
    }

    updateUI() {
      const unlocked = this.isUnlocked && this.encryptionKey;
      this.lockIndicator.textContent = unlocked ? "Unlocked" : "Locked";
      this.lockIndicator.className = `lock-indicator ${unlocked ? "unlocked" : "locked"}`;
      this.saveButton.disabled = !unlocked;
      this.lockButton.disabled = !unlocked;
      this.clearButton.disabled = !unlocked;
      this.noteContent.disabled = !unlocked;
      this.noteContent.placeholder = unlocked
        ? "Paste your Google backup codes here. They will be encrypted with your YubiKey PRF secret."
        : "Locked - sign in with your YubiKey first";
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

    randomBytes(length) {
      return Array.from(crypto.getRandomValues(new Uint8Array(length)));
    }

    loadLocalCredentialMeta() {
      try {
        const stored = localStorage.getItem(this.credentialStorageKey);
        if (!stored) return null;
        const meta = JSON.parse(stored);
        return this.normalizeCredentialMeta(meta);
      } catch {
        return null;
      }
    }

    saveLocalCredentialMeta(meta) {
      const normalized = this.normalizeCredentialMeta(meta);
      localStorage.setItem(this.credentialStorageKey, JSON.stringify(normalized));
      this.credentialMeta = normalized;
      return normalized;
    }

    normalizeCredentialMeta(meta) {
      if (!meta) return null;
      const credentialId = Array.isArray(meta) ? meta : meta.credentialId;
      const prfSalt = meta.prfSalt;
      if (!Array.isArray(credentialId) || !credentialId.length) return null;
      if (!Array.isArray(prfSalt) || prfSalt.length !== 32) return null;
      return {
        keyMode: "webauthn-prf",
        credentialId,
        prfSalt,
        rpId: meta.rpId || this.rpId(),
        created: meta.created || new Date().toISOString()
      };
    }

    encryptedMeta(encryptedData) {
      return this.normalizeCredentialMeta({
        credentialId: encryptedData.credentialId,
        prfSalt: encryptedData.prfSalt,
        rpId: encryptedData.rpId
      });
    }

    async setupYubiKey() {
      try {
        this.requireWebAuthn();
        if (this.loadLocalCredentialMeta()) {
          const replace = confirm("Replace the saved Backup Codes YubiKey PRF credential for this browser?");
          if (!replace) return;
        }

        const prfSalt = this.randomBytes(32);
        this.showStatus("Status: touch your YubiKey to register it for PRF encryption.", "info");
        const publicKeyOptions = {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          rp: { name: "GoblinPass Backup Codes", id: this.rpId() },
          user: {
            id: new TextEncoder().encode(crypto.randomUUID()),
            name: "goblinpass-backup-codes-local-user",
            displayName: "GoblinPass Backup Codes"
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            userVerification: "required"
          },
          extensions: {
            prf: {
              eval: { first: new Uint8Array(prfSalt) }
            }
          },
          timeout: 60000
        };

        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
        const extensionResults = credential.getClientExtensionResults?.() || {};
        if (!extensionResults.prf?.enabled) {
          throw new Error("This browser/security-key flow did not enable WebAuthn PRF.");
        }

        const meta = this.saveLocalCredentialMeta({
          credentialId: Array.from(new Uint8Array(credential.rawId)),
          prfSalt,
          rpId: this.rpId()
        });

        this.setupButton.textContent = "Replace YubiKey";
        await this.unlockWithMeta(meta);
        this.showStatus("Status: YubiKey PRF setup complete. New exports can be opened with this YubiKey in another supported browser.", "success");
      } catch (error) {
        this.showStatus(`Status: setup failed: ${error.message}`, "warning");
      }
    }

    async unlockWithMeta(meta) {
      this.requireWebAuthn();
      const normalized = this.normalizeCredentialMeta(meta);
      if (!normalized) throw new Error("Missing YubiKey PRF metadata.");

      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{
            id: new Uint8Array(normalized.credentialId),
            type: "public-key",
            transports: ["usb", "nfc", "ble"]
          }],
          extensions: {
            prf: {
              eval: { first: new Uint8Array(normalized.prfSalt) }
            }
          },
          timeout: 60000,
          userVerification: "required"
        }
      });

      const extensionResults = credential.getClientExtensionResults?.() || {};
      const prfSecret = extensionResults.prf?.results?.first;
      if (!prfSecret) {
        throw new Error("This browser/YubiKey did not return a PRF secret.");
      }

      this.encryptionKey = await crypto.subtle.importKey(
        "raw",
        prfSecret,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      this.credentialMeta = normalized;
      this.isUnlocked = true;
      this.updateUI();
      return true;
    }

    async encryptData(payload) {
      if (!this.encryptionKey || !this.credentialMeta) throw new Error("No YubiKey PRF key available.");

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        this.encryptionKey,
        new TextEncoder().encode(JSON.stringify(payload))
      );

      return {
        type: "goblinpass-google-backup-codes",
        version: "3.0",
        keyMode: "webauthn-prf",
        rpId: this.credentialMeta.rpId,
        credentialId: this.credentialMeta.credentialId,
        prfSalt: this.credentialMeta.prfSalt,
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        timestamp: Date.now()
      };
    }

    async decryptData(encryptedData) {
      if (!this.encryptionKey) throw new Error("No YubiKey PRF key available.");

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(encryptedData.iv) },
        this.encryptionKey,
        new Uint8Array(encryptedData.data)
      );

      const text = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(text);
      } catch {
        return { codes: text };
      }
    }

    async saveBackupCodes() {
      if (!this.isUnlocked) {
        this.showStatus("Status: sign in with your YubiKey first.", "warning");
        return;
      }

      try {
        const payload = {
          codes: this.noteContent.value,
          updated: new Date().toISOString()
        };
        const encrypted = await this.encryptData(payload);
        await this.saveEncryptedRecord(encrypted);
        this.lastSaved.textContent = new Date().toLocaleTimeString();
        this.showStatus("Status: backup codes encrypted with YubiKey PRF and saved locally.", "success");
      } catch (error) {
        this.showStatus(`Status: save failed: ${error.message}`, "warning");
      }
    }

    async saveEncryptedRecord(data) {
      await this.saveToIndexedDB(data);
      localStorage.setItem(this.localStorageKey, JSON.stringify(data));
    }

    async saveToIndexedDB(data) {
      if (!this.db) await this.initDatabase();
      return new Promise(resolve => {
        if (!this.db) {
          resolve(false);
          return;
        }
        const transaction = this.db.transaction([this.storeName], "readwrite");
        const store = transaction.objectStore(this.storeName);
        const request = store.put({ id: "main", data, updated: Date.now() });
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(false);
      });
    }

    async loadEncryptedRecord() {
      let encryptedData = null;
      if (this.db) encryptedData = await this.loadFromIndexedDB();
      if (!encryptedData) {
        const stored = localStorage.getItem(this.localStorageKey);
        if (stored) encryptedData = JSON.parse(stored);
      }
      return encryptedData;
    }

    async loadFromIndexedDB() {
      return new Promise(resolve => {
        if (!this.db) {
          resolve(null);
          return;
        }
        const transaction = this.db.transaction([this.storeName], "readonly");
        const store = transaction.objectStore(this.storeName);
        const request = store.get("main");
        request.onsuccess = () => resolve(request.result ? request.result.data : null);
        request.onerror = () => resolve(null);
      });
    }

    async unlockAndLoad() {
      try {
        this.showStatus("Status: touch your YubiKey to unlock.", "info");
        const encrypted = await this.loadEncryptedRecord();
        if (encrypted && encrypted.keyMode !== "webauthn-prf") {
          this.showStatus("Status: this saved vault uses the older browser-only encryption. Export or copy it before replacing it with a YubiKey PRF save.", "warning");
          return;
        }
        const meta = encrypted ? this.encryptedMeta(encrypted) : this.loadLocalCredentialMeta();
        if (!meta) {
          this.showStatus("Status: no YubiKey PRF vault is registered or imported yet.", "warning");
          return;
        }

        await this.unlockWithMeta(meta);
        this.saveLocalCredentialMeta(meta);

        if (encrypted) {
          const decrypted = await this.decryptData(encrypted);
          this.noteContent.value = decrypted.codes || "";
          this.showStatus("Status: backup codes loaded with your YubiKey PRF secret.", "success");
        } else {
          this.noteContent.value = "";
          this.showStatus("Status: signed in. No saved backup codes found yet.", "info");
        }
      } catch (error) {
        this.isUnlocked = false;
        this.updateUI();
        this.showStatus(`Status: authentication failed: ${error.message}`, "warning");
      }
    }

    lock() {
      this.isUnlocked = false;
      this.encryptionKey = null;
      this.noteContent.value = "";
      this.updateUI();
      this.showStatus("Status: locked. Codes cleared from the screen.", "warning");
    }

    async exportBackup() {
      let exportData = null;
      const stored = localStorage.getItem(this.localStorageKey);
      if (stored) exportData = JSON.parse(stored);
      if (!exportData) exportData = await this.loadFromIndexedDB();
      if (!exportData) {
        this.showStatus("Status: no encrypted backup codes to export.", "warning");
        return;
      }
      if (exportData.keyMode !== "webauthn-prf") {
        this.showStatus("Status: save again with YubiKey PRF before exporting a portable file.", "warning");
        return;
      }

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `goblinpass_backup_codes_prf_${Date.now()}.enc`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      this.showStatus("Status: encrypted PRF backup file exported.", "success");
    }

    async importBackup(file) {
      try {
        const encrypted = JSON.parse(await file.text());
        if (!encrypted.iv || !encrypted.data || encrypted.keyMode !== "webauthn-prf") {
          throw new Error("This is not a YubiKey PRF encrypted backup file.");
        }

        const meta = this.encryptedMeta(encrypted);
        if (!meta) throw new Error("The encrypted file is missing YubiKey PRF metadata.");

        this.showStatus("Status: touch the matching YubiKey to import this encrypted file.", "info");
        await this.unlockWithMeta(meta);
        const testDecrypt = await this.decryptData(encrypted);
        await this.saveEncryptedRecord(encrypted);
        this.saveLocalCredentialMeta(meta);
        this.setupButton.textContent = "Replace YubiKey";
        this.noteContent.value = testDecrypt.codes || "";
        this.showStatus("Status: encrypted file imported and decrypted with your YubiKey PRF secret.", "success");
      } catch (error) {
        this.showStatus(`Status: import failed: ${error.message}`, "warning");
      }
    }

    purgeEntries() {
      const ok = confirm("Delete all encrypted backup codes from this browser? This cannot be undone.");
      if (!ok) return;
      localStorage.removeItem(this.localStorageKey);
      if (this.db) {
        const transaction = this.db.transaction([this.storeName], "readwrite");
        transaction.objectStore(this.storeName).delete("main");
      }
      this.noteContent.value = "";
      this.showStatus("Status: encrypted backup codes purged from this browser.", "warning");
    }
  }

  if (document.getElementById("setupBtn")) {
    new YubiKeyBackupCodesVault();
  }
})();
