"use strict";

const assert = require("node:assert/strict");

global.window = {};
require("../gen4/qr.js");
const Reader = require("../qr-scanner/qr-reader.js");

[
  "Goblin7!Pass_word",
  "aZ9%",
  "Longer-password_42!withSymbols"
].forEach(password => {
  const modules = window.GoblinPassQrV4.matrix(password);
  assert.equal(Reader.decodeModules(modules), password);
});

const imagePassword = "CameraScan9!_test";
const imageModules = window.GoblinPassQrV4.matrix(imagePassword);
const scale = 6;
const quietZone = 4;
const imageSize = (33 + quietZone * 2) * scale;
const imageData = { width: imageSize, height: imageSize, data: new Uint8ClampedArray(imageSize * imageSize * 4).fill(255) };
imageModules.forEach((row, y) => row.forEach((dark, x) => {
  if (!dark) return;
  for (let offsetY = 0; offsetY < scale; offsetY += 1) {
    for (let offsetX = 0; offsetX < scale; offsetX += 1) {
      const pixel = ((y + quietZone) * scale + offsetY) * imageSize + (x + quietZone) * scale + offsetX;
      imageData.data[pixel * 4] = 0;
      imageData.data[pixel * 4 + 1] = 0;
      imageData.data[pixel * 4 + 2] = 0;
    }
  }
}));
assert.equal(Reader.decodeImageData(imageData), imagePassword);

const rotatedImageData = { width: imageSize, height: imageSize, data: new Uint8ClampedArray(imageData.data.length) };
for (let y = 0; y < imageSize; y += 1) {
  for (let x = 0; x < imageSize; x += 1) {
    const sourcePixel = (y * imageSize + x) * 4;
    const rotatedPixel = (x * imageSize + (imageSize - 1 - y)) * 4;
    for (let channel = 0; channel < 4; channel += 1) rotatedImageData.data[rotatedPixel + channel] = imageData.data[sourcePixel + channel];
  }
}
assert.equal(Reader.decodeImageData(rotatedImageData), imagePassword);

assert.throws(() => Reader.decodeModules(Array.from({ length: 33 }, () => Array(33).fill(false))));
console.log("Gen 4 QR reader tests passed.");
