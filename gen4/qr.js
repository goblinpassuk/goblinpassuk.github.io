(function () {
  "use strict";

  const SIZE = 33;
  const DATA_CODEWORDS = 80;
  const ECC_CODEWORDS = 20;

  function initGaloisField() {
    const exp = new Array(512);
    const log = new Array(256);
    let value = 1;
    for (let index = 0; index < 255; index += 1) {
      exp[index] = value;
      log[value] = index;
      value <<= 1;
      if (value & 0x100) value ^= 0x11d;
    }
    for (let index = 255; index < 512; index += 1) exp[index] = exp[index - 255];
    return { exp, log };
  }

  const GF = initGaloisField();

  function multiply(a, b) {
    if (!a || !b) return 0;
    return GF.exp[GF.log[a] + GF.log[b]];
  }

  function generatorPolynomial(degree) {
    let polynomial = [1];
    for (let index = 0; index < degree; index += 1) {
      const next = new Array(polynomial.length + 1).fill(0);
      for (let offset = 0; offset < polynomial.length; offset += 1) {
        next[offset] ^= polynomial[offset];
        next[offset + 1] ^= multiply(polynomial[offset], GF.exp[index]);
      }
      polynomial = next;
    }
    return polynomial;
  }

  function errorCorrection(data, degree) {
    const generator = generatorPolynomial(degree);
    const correction = new Array(degree).fill(0);
    data.forEach(byte => {
      const factor = byte ^ correction.shift();
      correction.push(0);
      for (let index = 0; index < degree; index += 1) correction[index] ^= multiply(generator[index + 1], factor);
    });
    return correction;
  }

  function pushBits(bits, value, length) {
    for (let index = length - 1; index >= 0; index -= 1) bits.push((value >>> index) & 1);
  }

  function dataCodewords(text) {
    const bytes = [...new TextEncoder().encode(text)];
    if (bytes.length > 78) throw new Error("QR data is too long.");
    const bits = [];
    pushBits(bits, 0b0100, 4);
    pushBits(bits, bytes.length, 8);
    bytes.forEach(byte => pushBits(bits, byte, 8));
    const maximumBits = DATA_CODEWORDS * 8;
    pushBits(bits, 0, Math.min(4, maximumBits - bits.length));
    while (bits.length % 8) bits.push(0);
    const output = [];
    for (let index = 0; index < bits.length; index += 8) {
      output.push(bits.slice(index, index + 8).reduce((value, bit) => (value << 1) | bit, 0));
    }
    for (let pad = 0xec; output.length < DATA_CODEWORDS; pad = pad === 0xec ? 0x11 : 0xec) output.push(pad);
    return output;
  }

  function formatBits(mask) {
    const data = (0b01 << 3) | mask;
    let value = data << 10;
    for (let index = 14; index >= 10; index -= 1) {
      if ((value >>> index) & 1) value ^= 0x537 << (index - 10);
    }
    return ((data << 10) | value) ^ 0x5412;
  }

  function matrix(text) {
    const modules = Array.from({ length: SIZE }, () => Array(SIZE).fill(null));
    const set = (x, y, dark) => {
      if (x >= 0 && y >= 0 && x < SIZE && y < SIZE) modules[y][x] = !!dark;
    };
    const finder = (x, y) => {
      for (let row = -1; row <= 7; row += 1) {
        for (let column = -1; column <= 7; column += 1) {
          const edge = column === -1 || row === -1 || column === 7 || row === 7;
          const dark = !edge && (column === 0 || row === 0 || column === 6 || row === 6 || (column >= 2 && column <= 4 && row >= 2 && row <= 4));
          set(x + column, y + row, dark);
        }
      }
    };
    const alignment = (centerX, centerY) => {
      for (let row = -2; row <= 2; row += 1) {
        for (let column = -2; column <= 2; column += 1) set(centerX + column, centerY + row, Math.max(Math.abs(column), Math.abs(row)) !== 1);
      }
    };

    finder(0, 0);
    finder(SIZE - 7, 0);
    finder(0, SIZE - 7);
    alignment(26, 26);
    for (let index = 8; index < SIZE - 8; index += 1) {
      set(index, 6, index % 2 === 0);
      set(6, index, index % 2 === 0);
    }
    set(8, SIZE - 8, true);

    const reserved = [
      ...Array.from({ length: 6 }, (_, index) => [8, index]),
      [8, 7], [8, 8], [7, 8],
      ...Array.from({ length: 6 }, (_, index) => [5 - index, 8]),
      ...Array.from({ length: 8 }, (_, index) => [SIZE - 1 - index, 8]),
      ...Array.from({ length: 7 }, (_, index) => [8, SIZE - 7 + index])
    ];
    reserved.forEach(([x, y]) => set(x, y, false));

    const codewords = dataCodewords(text);
    const bits = [];
    codewords.concat(errorCorrection(codewords, ECC_CODEWORDS)).forEach(byte => pushBits(bits, byte, 8));
    let bitIndex = 0;
    let upward = true;
    for (let x = SIZE - 1; x > 0; x -= 2) {
      if (x === 6) x -= 1;
      for (let index = 0; index < SIZE; index += 1) {
        const y = upward ? SIZE - 1 - index : index;
        for (let offset = 0; offset < 2; offset += 1) {
          const column = x - offset;
          if (modules[y][column] !== null) continue;
          const bit = bits[bitIndex++] || 0;
          set(column, y, bit ^ ((column + y) % 2 === 0 ? 1 : 0));
        }
      }
      upward = !upward;
    }

    const format = formatBits(0);
    const formatBit = index => ((format >>> index) & 1) === 1;
    for (let index = 0; index < 6; index += 1) set(8, index, formatBit(index));
    set(8, 7, formatBit(6));
    set(8, 8, formatBit(7));
    set(7, 8, formatBit(8));
    for (let index = 9; index < 15; index += 1) set(14 - index, 8, formatBit(index));
    for (let index = 0; index < 8; index += 1) set(SIZE - 1 - index, 8, formatBit(index));
    for (let index = 8; index < 15; index += 1) set(8, SIZE - 15 + index, formatBit(index));
    return modules;
  }

  function draw(canvas, text) {
    if (!canvas) throw new Error("QR canvas is unavailable.");
    const modules = matrix(text);
    const scale = 6;
    const quietZone = 4;
    const size = (SIZE + quietZone * 2) * scale;
    canvas.width = size;
    canvas.height = size;
    const context = canvas.getContext("2d");
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, size, size);
    context.fillStyle = "#000000";
    modules.forEach((row, y) => row.forEach((dark, x) => {
      if (dark) context.fillRect((x + quietZone) * scale, (y + quietZone) * scale, scale, scale);
    }));
  }

  window.GoblinPassQrV4 = { draw, matrix };
})();
