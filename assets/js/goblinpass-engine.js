"use strict";

const GOBLINPASS_ENGINE_VERSION = "2.0.0";
const GP_CHARSETS = [
  { key: "lower", chars: "abcdefghijklmnopqrstuvwxyz" },
  { key: "upper", chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
  { key: "nums", chars: "0123456789" },
  { key: "symbols", chars: "%!@#$_-" }
];
const GP_MEMORABLE_WORDS = [
  "Amber", "Anchor", "Aspen", "Atlas", "Autumn", "Beacon", "Berry", "Blossom",
  "Bridge", "Bronze", "Canyon", "Cedar", "Cherry", "Cloud", "Comet", "Copper",
  "Crystal", "Daisy", "Delta", "Echo", "Ember", "Falcon", "Forest", "Frost",
  "Galaxy", "Garden", "Harbor", "Hazel", "Hidden", "Indigo", "Island", "Jasper",
  "Juniper", "Kernel", "Lagoon", "Lantern", "Maple", "Marble", "Meadow", "Meteor",
  "Midnight", "Mint", "Mountain", "Nectar", "Nova", "Ocean", "Olive", "Onyx",
  "Orbit", "Pebble", "Pepper", "Phoenix", "Pine", "Pixel", "Planet", "Purple",
  "Quartz", "River", "Rocket", "Saffron", "Shadow", "Silver", "Solstice", "Spark",
  "Stone", "Storm", "Summit", "Sunset", "Thistle", "Thunder", "Topaz", "Tulip",
  "Velvet", "Violet", "Willow", "Winter", "Zephyr", "Hammer", "Compass", "Puzzle",
  "Signal", "Castle", "Engine", "Voyage", "Button", "Cobalt"
];

async function gpSha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

async function gpCharFromSet(seed, set, round) {
  const hex = await gpSha256Hex(`${seed}|required|${set.key}|${round}`);
  return set.chars[parseInt(hex.slice(0, 8), 16) % set.chars.length];
}

async function gpDeterministicShuffle(items, seed) {
  const scored = [];
  for (let i = 0; i < items.length; i += 1) {
    scored.push({ value: items[i], score: await gpSha256Hex(`${seed}|shuffle|${i}|${items[i]}`) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value).join("");
}

async function gpDeterministicSetOrder(sets, seed, round) {
  const scored = [];
  for (let i = 0; i < sets.length; i += 1) {
    scored.push({ value: sets[i], score: await gpSha256Hex(`${seed}|set-order|${round}|${sets[i].key}`) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value);
}

async function gpDistributedCharacters(seed, sets, length) {
  const out = [];
  const minimumPerSet = Math.max(1, Math.min(2, Math.floor(length / sets.length)));
  for (const set of sets) {
    for (let i = 0; i < minimumPerSet && out.length < length; i += 1) {
      out.push(await gpCharFromSet(seed, set, i));
    }
  }
  let round = 0;
  while (out.length < length) {
    const orderedSets = await gpDeterministicSetOrder(sets, seed, round);
    for (const set of orderedSets) {
      if (out.length >= length) break;
      out.push(await gpCharFromSet(seed, set, minimumPerSet + round));
    }
    round += 1;
  }
  return out;
}

async function gpMemorableWord(seed, round) {
  const hex = await gpSha256Hex(`${seed}|word|${round}`);
  return GP_MEMORABLE_WORDS[parseInt(hex.slice(0, 8), 16) % GP_MEMORABLE_WORDS.length];
}

async function gpMemorablePassword(seed, strength) {
  const wordCount = strength === "easy" ? 3 : 4;
  const words = [];
  for (let i = 0; i < wordCount; i += 1) words.push(await gpMemorableWord(seed, i));
  if (strength === "strong") {
    const digitHex = await gpSha256Hex(`${seed}|digit`);
    const symbolHex = await gpSha256Hex(`${seed}|symbol`);
    const symbols = "!@#$%";
    return `${words.join("-")}${symbols[parseInt(symbolHex.slice(0, 8), 16) % symbols.length]}${parseInt(digitHex.slice(0, 8), 16) % 10}`;
  }
  return words.join("-");
}

async function goblinPassGenerate(siteId, masterPassword, options = {}) {
  const length = Math.max(8, Math.min(64, parseInt(options.length || "16", 10)));
  const counter = Math.max(1, Math.min(999, parseInt(options.counter || "1", 10)));
  const selectedKeys = options.selectedKeys && options.selectedKeys.length ? options.selectedKeys : ["lower", "upper", "nums", "symbols"];
  const sets = GP_CHARSETS.filter(set => selectedKeys.includes(set.key));
  const optionKey = sets.map(set => set.key).join(",");
  const normalizedSiteId = String(siteId).trim().toLowerCase();
  const securityKey = String(options.securityKey || "");
  const trustedDeviceKey = String(options.trustedDeviceKey || "");
  const googleSubjectId = String(options.googleSubjectId || "");
  const yubiKeyFactor = String(options.yubiKeyFactor || "");
  const passwordStyle = options.passwordStyle === "memorable" ? "memorable" : "maximum";
  const memorableStrength = ["easy", "standard", "strong"].includes(options.memorableStrength) ? options.memorableStrength : "standard";
  if (passwordStyle === "memorable") {
    const memorableSeed = yubiKeyFactor
      ? `GPMEMV1Y|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${yubiKeyFactor}|${memorableStrength}`
      : `GPMEMV1|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${memorableStrength}`;
    return gpMemorablePassword(memorableSeed, memorableStrength);
  }
  const seed = yubiKeyFactor
    ? `GPIDV2Y|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${yubiKeyFactor}|${optionKey}`
    : googleSubjectId && trustedDeviceKey
    ? `GPIDV2TG|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${optionKey}`
    : googleSubjectId
    ? `GPIDV2G|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${googleSubjectId}|${optionKey}`
    : trustedDeviceKey
    ? `GPIDV2T|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${trustedDeviceKey}|${optionKey}`
    : securityKey
    ? `GPIDV2K|${normalizedSiteId}|${counter}|${masterPassword}|${securityKey}|${optionKey}`
    : `GPIDV2|${normalizedSiteId}|${counter}|${masterPassword}|${optionKey}`;
  const out = await gpDistributedCharacters(seed, sets, length);
  return gpDeterministicShuffle(out, seed);
}

window.goblinPassGenerate = goblinPassGenerate;
window.GOBLINPASS_ENGINE_VERSION = GOBLINPASS_ENGINE_VERSION;
