import type { LegacyVaultV1, VaultRecordV2 } from "./types.js";

const DATABASE = "goblinpass-gen5-secure";
const DATABASE_VERSION = 2;
const VAULTS = "vaults";
const ACTIVE_KEY = "active";

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted."));
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed."));
  });
}

async function openDatabase(): Promise<IDBDatabase> {
  const request = indexedDB.open(DATABASE, DATABASE_VERSION);
  request.onupgradeneeded = () => {
    const database = request.result;
    if (!database.objectStoreNames.contains(VAULTS)) database.createObjectStore(VAULTS);
  };
  return requestResult(request);
}

export class VaultStorage {
  async read(): Promise<VaultRecordV2 | undefined> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(VAULTS, "readonly", { durability: "strict" });
      return await requestResult(transaction.objectStore(VAULTS).get(ACTIVE_KEY)) as VaultRecordV2 | undefined;
    } finally {
      database.close();
    }
  }

  async writeAtomic(record: VaultRecordV2, expectedRevision: number | null): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(VAULTS, "readwrite", { durability: "strict" });
      const store = transaction.objectStore(VAULTS);
      const current = await requestResult(store.get(ACTIVE_KEY)) as VaultRecordV2 | undefined;
      const currentRevision = current?.revision ?? null;
      if (currentRevision !== expectedRevision) {
        transaction.abort();
        throw new DOMException("Vault changed in another tab.", "InvalidStateError");
      }
      store.put(structuredClone(record), ACTIVE_KEY);
      await transactionComplete(transaction);
    } finally {
      database.close();
    }
  }

  async remove(): Promise<void> {
    const database = await openDatabase();
    try {
      const transaction = database.transaction(VAULTS, "readwrite", { durability: "strict" });
      transaction.objectStore(VAULTS).delete(ACTIVE_KEY);
      await transactionComplete(transaction);
    } finally {
      database.close();
    }
  }

  async readLegacy(): Promise<LegacyVaultV1 | undefined> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("goblinpass-gen5", 1);
      request.onsuccess = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains("vault")) {
          database.close();
          resolve(undefined);
          return;
        }
        const transaction = database.transaction("vault", "readonly");
        const get = transaction.objectStore("vault").get("master-password");
        get.onsuccess = () => { database.close(); resolve(get.result as LegacyVaultV1 | undefined); };
        get.onerror = () => { database.close(); reject(get.error); };
      };
      request.onerror = () => reject(request.error);
    });
  }

  async removeLegacy(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open("goblinpass-gen5", 1);
      request.onsuccess = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains("vault")) { database.close(); resolve(); return; }
        const transaction = database.transaction("vault", "readwrite");
        transaction.objectStore("vault").delete("master-password");
        transaction.oncomplete = () => { database.close(); resolve(); };
        transaction.onerror = () => { database.close(); reject(transaction.error); };
        transaction.onabort = () => { database.close(); reject(transaction.error); };
      };
      request.onerror = () => reject(request.error);
    });
  }
}
