(function () {
  "use strict";

  class YubiKeyBackupCodesVault {
    constructor() {
      this.encryptionKey = null;
      this.credentialId = null;
      this.isUnlocked = false;
      this.dbName = "GoblinPassBackupCodesDB";
      this.storeName = "encryptedBackupCodes";
      this.db = null;
      this.credentialStorageKey = "goblinpass_backup_codes_yubikey_credential_id";
      this.localStorageKey = "goblinpass_backup_codes_encrypted_backup";

      this.status = document.getElementById("status");
      this.setupButton = document.getElementById("setupBtn");
      this.unlockButton = document.getElementById("unlockBtn");
      this.saveButton = document.getElementById("saveBtn");
      this.lockButton = document.getElementById("lockBtn");
      this.clearButton = document.getElementById("clearBtn");
      this.exportButton = document.getElementById("exportBtn");
      this.importButton = document.getElementById("importBtn");
      this.purgeButton = document.getElementById("purgeBtn");
      this.removeUsedButton = document.getElementById("removeUsedBtn");
      this.fileInput = document.getElementById("fileInput");
      this.emailInput = document.getElementById("accountEmail");
      this.noteContent = document.getElementById("noteContent");
      this.lockIndicator = document.getElementById("lockIndicator");
      this.lastSaved = document.getElementById("lastSaved");
      this.codeList = document.getElementById("backupCodeList");

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
      this.saveButton.addEventListener("click", () => this.saveToLocalStorage());
      this.lockButton.addEventListener("click", () => this.lock());
      this.clearButton.addEventListener("click", () => {
        this.noteContent.value = "";
        this.renderCodeList([]);
      });
      this.exportButton.addEventListener("click", () => this.exportBackup());
      this.importButton.addEventListener("click", () => this.fileInput.click());
      this.fileInput.addEventListener("change", event => {
        const file = event.target.files?.[0];
        if (file) this.importBackup(file);
        this.fileInput.value = "";
      });
      this.purgeButton.addEventListener("click", () => this.purgeEntries());
      this.removeUsedButton.addEventListener("click", () => this.removeSelectedCodes());
      this.noteContent.addEventListener("input", () => this.renderCodeList(this.codesFromText(this.noteContent.value)));
    }

    refreshInitialState() {
      if (localStorage.getItem(this.credentialStorageKey)) {
        this.setupButton.textContent = "Replace YubiKey";
        this.showStatus("Status: YubiKey is registered. Sign in to show or save backup codes.", "success");
      } else {
        this.showStatus("Status: ready. Register your YubiKey first.", "info");
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
      this.removeUsedButton.disabled = !unlocked;
      this.noteContent.disabled = !unlocked;
      this.emailInput.disabled = !unlocked;
      this.noteContent.placeholder = unlocked
        ? "Paste your Google backup codes here. They will be encrypted before saving."
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

    async setupYubiKey() {
      try {
        this.requireWebAuthn();
        if (localStorage.getItem(this.credentialStorageKey)) {
          const replace = confirm("Replace the saved Backup Codes YubiKey credential for this browser?");
          if (!replace) return;
        }

        this.showStatus("Status: touch your YubiKey to register it for Backup Codes.", "info");
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const userId = crypto.randomUUID();
        const publicKeyOptions = {
          challenge,
          rp: { name: "GoblinPass Backup Codes", id: this.rpId() },
          user: {
            id: new TextEncoder().encode(userId),
            name: "goblinpass-backup-codes-local-user",
            displayName: "GoblinPass Backup Codes"
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            userVerification: "required"
          },
          timeout: 60000
        };

        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
        this.credentialId = Array.from(new Uint8Array(credential.rawId));
        localStorage.setItem(this.credentialStorageKey, JSON.stringify(this.credentialId));
        this.setupButton.textContent = "Replace YubiKey";

        await this.deriveStableKey();
        this.showStatus("Status: YubiKey setup complete. Sign in to unlock or save backup codes.", "success");
        this.updateUI();
      } catch (error) {
        this.showStatus(`Status: setup failed: ${error.message}`, "warning");
      }
    }

    async deriveStableKey() {
      const storedCredentialId = JSON.parse(localStorage.getItem(this.credentialStorageKey) || "[]");
      if (!storedCredentialId.length) return null;

      const credentialBytes = new Uint8Array(storedCredentialId);
      const salt = new TextEncoder().encode("GoblinPassBackupCodesYubiKeyVault2026");
      const combined = new Uint8Array(credentialBytes.length + salt.length);
      combined.set(credentialBytes, 0);
      combined.set(salt, credentialBytes.length);

      const keyMaterial = await crypto.subtle.digest("SHA-256", combined);
      this.encryptionKey = await crypto.subtle.importKey(
        "raw",
        keyMaterial,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
      );
      return this.encryptionKey;
    }

    async authenticate() {
      try {
        this.requireWebAuthn();
        const storedCredentialId = JSON.parse(localStorage.getItem(this.credentialStorageKey) || "[]");
        if (!storedCredentialId.length) {
          throw new Error("No Backup Codes YubiKey is registered. Run setup first.");
        }

        const requestOptions = {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials: [{
            id: new Uint8Array(storedCredentialId),
            type: "public-key",
            transports: ["usb", "nfc", "ble"]
          }],
          timeout: 60000,
          userVerification: "required"
        };

        await navigator.credentials.get({ publicKey: requestOptions });
        await this.deriveStableKey();
        this.isUnlocked = true;
        this.updateUI();
        return true;
      } catch {
        this.isUnlocked = false;
        this.updateUI();
        return false;
      }
    }

    async encryptData(payload) {
      if (!this.encryptionKey) await this.deriveStableKey();
      if (!this.encryptionKey) throw new Error("No encryption key available.");

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        this.encryptionKey,
        new TextEncoder().encode(JSON.stringify(payload))
      );

      return {
        type: "goblinpass-google-backup-codes",
        version: "2.0",
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
        timestamp: Date.now()
      };
    }

    async decryptData(encryptedData) {
      if (!this.encryptionKey) await this.deriveStableKey();
      if (!this.encryptionKey) throw new Error("No encryption key available.");

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(encryptedData.iv) },
        this.encryptionKey,
        new Uint8Array(encryptedData.data)
      );

      const text = new TextDecoder().decode(decrypted);
      try {
        return JSON.parse(text);
      } catch {
        return { email: "", codes: text };
      }
    }

    async saveToLocalStorage() {
      if (!this.isUnlocked) {
        this.showStatus("Status: sign in with your YubiKey first.", "warning");
        return;
      }

      try {
        const payload = {
          email: this.emailInput.value.trim(),
          codes: this.noteContent.value,
          updated: new Date().toISOString()
        };
        const encrypted = await this.encryptData(payload);
        await this.saveToIndexedDB(encrypted);
        localStorage.setItem(this.localStorageKey, JSON.stringify(encrypted));
        this.lastSaved.textContent = new Date().toLocaleTimeString();
        this.showStatus("Status: backup codes encrypted and saved locally.", "success");
      } catch (error) {
        this.showStatus(`Status: save failed: ${error.message}`, "warning");
      }
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

    async loadFromLocalStorage() {
      let encryptedData = null;
      if (this.db) encryptedData = await this.loadFromIndexedDB();
      if (!encryptedData) {
        const stored = localStorage.getItem(this.localStorageKey);
        if (stored) encryptedData = JSON.parse(stored);
      }
      if (!encryptedData) return null;
      return this.decryptData(encryptedData);
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
      this.showStatus("Status: touch your YubiKey to unlock.", "info");
      const authenticated = await this.authenticate();
      if (!authenticated) {
        this.showStatus("Status: authentication failed. Make sure you use the registered YubiKey.", "warning");
        return;
      }

      const decrypted = await this.loadFromLocalStorage();
      if (decrypted) {
        this.emailInput.value = decrypted.email || "";
        this.noteContent.value = decrypted.codes || "";
        this.renderCodeList(this.codesFromText(this.noteContent.value));
        this.showStatus("Status: backup codes loaded and decrypted locally.", "success");
      } else {
        this.emailInput.value = "";
        this.noteContent.value = "";
        this.renderCodeList([]);
        this.showStatus("Status: signed in. No saved backup codes found yet.", "info");
      }
    }

    lock() {
      this.isUnlocked = false;
      this.encryptionKey = null;
      this.emailInput.value = "";
      this.noteContent.value = "";
      this.renderCodeList([]);
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

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `goblinpass_backup_codes_${Date.now()}.enc`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      this.showStatus("Status: encrypted backup file exported.", "success");
    }

    async importBackup(file) {
      if (!this.isUnlocked) {
        this.showStatus("Status: sign in with your YubiKey before importing.", "warning");
        return;
      }

      try {
        const encrypted = JSON.parse(await file.text());
        if (!encrypted.iv || !encrypted.data) throw new Error("Invalid encrypted backup file.");
        const testDecrypt = await this.decryptData(encrypted);
        await this.saveToIndexedDB(encrypted);
        localStorage.setItem(this.localStorageKey, JSON.stringify(encrypted));
        this.emailInput.value = testDecrypt.email || "";
        this.noteContent.value = testDecrypt.codes || "";
        this.renderCodeList(this.codesFromText(this.noteContent.value));
        this.showStatus("Status: encrypted backup imported and decrypted.", "success");
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
      this.emailInput.value = "";
      this.noteContent.value = "";
      this.renderCodeList([]);
      this.showStatus("Status: encrypted backup codes purged from this browser.", "warning");
    }

    codesFromText(text) {
      return String(text || "")
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);
    }

    renderCodeList(codes) {
      if (!this.codeList) return;
      if (!codes.length) {
        this.codeList.textContent = this.isUnlocked
          ? "No backup codes in the editor."
          : "Unlock your backup codes to manage individual entries.";
        return;
      }
      this.codeList.innerHTML = "";
      codes.forEach((code, index) => {
        const label = document.createElement("label");
        label.className = "backup-code-row";
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = String(index);
        checkbox.addEventListener("change", () => label.classList.toggle("is-used", checkbox.checked));
        const value = document.createElement("span");
        value.textContent = code;
        label.append(checkbox, value);
        this.codeList.appendChild(label);
      });
    }

    removeSelectedCodes() {
      const codes = this.codesFromText(this.noteContent.value);
      const selected = Array.from(this.codeList.querySelectorAll("input[type='checkbox']:checked"))
        .map(input => Number(input.value));
      if (!selected.length) {
        this.showStatus("Status: tick at least one used code first.", "warning");
        return;
      }
      const selectedSet = new Set(selected);
      const remaining = codes.filter((_, index) => !selectedSet.has(index));
      this.noteContent.value = remaining.join("\n");
      this.renderCodeList(remaining);
      this.showStatus("Status: selected codes removed from the editor. Press save to encrypt the change.", "success");
    }
  }

  if (document.getElementById("setupBtn")) {
    new YubiKeyBackupCodesVault();
  }
})();
