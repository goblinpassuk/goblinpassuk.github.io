import { base64url, constantTimeEqual, fromBase64url, randomBytes, utf8, wipe } from "./crypto.js";

interface PrfOutput { enabled?: boolean; results?: { first?: ArrayBuffer }; }
interface CredentialExtensions { prf?: PrfOutput; credProps?: { rk?: boolean }; }

export interface RegisteredPasskey {
  credentialId: Uint8Array;
  transports: AuthenticatorTransport[];
  prfOutput: Uint8Array;
}

export async function webAuthnSupport(): Promise<{ available: boolean; reason?: string }> {
  if (!isSecureContext || !crypto?.subtle || !window.PublicKeyCredential || !navigator.credentials) {
    return { available: false, reason: "Secure-context WebAuthn and Web Crypto are required." };
  }
  if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function" &&
      !await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
    return { available: false, reason: "No user-verifying platform authenticator is available." };
  }
  if (typeof PublicKeyCredential.getClientCapabilities === "function") {
    const capabilities = await PublicKeyCredential.getClientCapabilities();
    if (capabilities["extension:prf"] === false) return { available: false, reason: "WebAuthn PRF is unavailable." };
  }
  return { available: true };
}

function verifyClientData(credential: PublicKeyCredential, expectedType: "webauthn.create" | "webauthn.get", challenge: Uint8Array): void {
  const response = credential.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
  const parsed = JSON.parse(new TextDecoder().decode(response.clientDataJSON)) as {
    type?: string; challenge?: string; origin?: string; crossOrigin?: boolean;
  };
  const returnedChallenge = fromBase64url(parsed.challenge ?? "");
  const matches = constantTimeEqual(returnedChallenge, challenge);
  wipe(returnedChallenge);
  if (!matches || parsed.type !== expectedType || parsed.origin !== location.origin || parsed.crossOrigin === true) {
    throw new DOMException("WebAuthn client data validation failed.", "SecurityError");
  }
}

export async function registerPasskey(prfSalt: Uint8Array, excludeIds: Uint8Array[] = []): Promise<RegisteredPasskey> {
  if (prfSalt.length !== 32) throw new Error("PRF salt must be 256 bits.");
  const challenge = randomBytes(32);
  const userId = randomBytes(32);
  try {
    const created = await navigator.credentials.create({ publicKey: {
      challenge,
      rp: { name: "GoblinPass", id: location.hostname },
      user: { id: userId, name: `local-vault-${base64url(userId)}`, displayName: "GoblinPass local vault" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      excludeCredentials: excludeIds.map(id => ({ type: "public-key", id })),
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required"
      },
      attestation: "none",
      timeout: 120_000,
      extensions: { prf: { eval: { first: prfSalt } }, credProps: true }
    } }) as PublicKeyCredential | null;
    if (!created) throw new DOMException("Passkey creation returned no credential.", "NotAllowedError");
    verifyClientData(created, "webauthn.create", challenge);
    const extensions = created.getClientExtensionResults() as CredentialExtensions;
    if (!extensions.prf?.enabled || extensions.credProps?.rk === false) {
      throw new DOMException("The created passkey lacks required PRF or resident-key support.", "NotSupportedError");
    }
    const credentialId = new Uint8Array(created.rawId.slice(0));
    const immediate = extensions.prf.results?.first;
    const prfOutput = immediate ? new Uint8Array(immediate.slice(0)) : await evaluatePasskey(credentialId, prfSalt);
    const transports = ((created.response as AuthenticatorAttestationResponse).getTransports?.() ?? []) as AuthenticatorTransport[];
    return { credentialId, transports, prfOutput };
  } finally {
    wipe(challenge, userId);
  }
}

export async function evaluatePasskey(credentialId: Uint8Array, prfSalt: Uint8Array): Promise<Uint8Array> {
  const challenge = randomBytes(32);
  try {
    const assertion = await navigator.credentials.get({ publicKey: {
      challenge,
      rpId: location.hostname,
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      timeout: 120_000,
      extensions: { prf: { eval: { first: prfSalt } } }
    } }) as PublicKeyCredential | null;
    if (!assertion) throw new DOMException("Passkey authentication returned no assertion.", "NotAllowedError");
    verifyClientData(assertion, "webauthn.get", challenge);
    if (!constantTimeEqual(new Uint8Array(assertion.rawId), credentialId)) {
      throw new DOMException("Unexpected credential returned.", "SecurityError");
    }
    const extensions = assertion.getClientExtensionResults() as CredentialExtensions;
    const result = extensions.prf?.results?.first;
    if (!result) throw new DOMException("The passkey did not return a PRF result.", "NotSupportedError");
    return new Uint8Array(result.slice(0));
  } finally {
    wipe(challenge);
  }
}

export function credentialIdString(id: Uint8Array): string {
  return base64url(id);
}
