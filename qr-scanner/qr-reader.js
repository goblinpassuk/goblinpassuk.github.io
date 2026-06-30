(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.GoblinPassQrReader = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  const SIZE = 33;
  const DATA_CODEWORDS = 80;

  function markReserved() {
    const reserved = Array.from({ length: SIZE }, () => Array(SIZE).fill(false));
    const mark = (x, y) => {
      if (x >= 0 && y >= 0 && x < SIZE && y < SIZE) reserved[y][x] = true;
    };
    const finder = (x, y) => {
      for (let row = -1; row <= 7; row += 1) {
        for (let column = -1; column <= 7; column += 1) mark(x + column, y + row);
      }
    };
    finder(0, 0);
    finder(SIZE - 7, 0);
    finder(0, SIZE - 7);
    for (let row = -2; row <= 2; row += 1) {
      for (let column = -2; column <= 2; column += 1) mark(26 + column, 26 + row);
    }
    for (let index = 8; index < SIZE - 8; index += 1) {
      mark(index, 6);
      mark(6, index);
    }
    mark(8, SIZE - 8);
    [
      ...Array.from({ length: 6 }, (_, index) => [8, index]),
      [8, 7], [8, 8], [7, 8],
      ...Array.from({ length: 6 }, (_, index) => [5 - index, 8]),
      ...Array.from({ length: 8 }, (_, index) => [SIZE - 1 - index, 8]),
      ...Array.from({ length: 7 }, (_, index) => [8, SIZE - 7 + index])
    ].forEach(([x, y]) => mark(x, y));
    return reserved;
  }

  const RESERVED = markReserved();

  function readDataBits(modules) {
    if (!Array.isArray(modules) || modules.length !== SIZE || modules.some(row => !Array.isArray(row) || row.length !== SIZE)) {
      throw new Error("Invalid GoblinPass QR matrix.");
    }
    const bits = [];
    let upward = true;
    for (let x = SIZE - 1; x > 0; x -= 2) {
      if (x === 6) x -= 1;
      for (let index = 0; index < SIZE; index += 1) {
        const y = upward ? SIZE - 1 - index : index;
        for (let offset = 0; offset < 2; offset += 1) {
          const column = x - offset;
          if (RESERVED[y][column]) continue;
          const masked = Boolean(modules[y][column]);
          bits.push(Number(masked) ^ Number((column + y) % 2 === 0));
        }
      }
      upward = !upward;
    }
    return bits.slice(0, DATA_CODEWORDS * 8);
  }

  function bitsToNumber(bits, start, length) {
    let value = 0;
    for (let index = 0; index < length; index += 1) value = (value << 1) | (bits[start + index] || 0);
    return value;
  }

  function decodeModules(modules) {
    const bits = readDataBits(modules);
    if (bitsToNumber(bits, 0, 4) !== 0b0100) throw new Error("QR code is not in GoblinPass byte format.");
    const length = bitsToNumber(bits, 4, 8);
    if (!length || length > 78 || 12 + length * 8 > bits.length) throw new Error("QR code has an invalid payload length.");
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) bytes[index] = bitsToNumber(bits, 12 + index * 8, 8);
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function otsuThreshold(gray) {
    const histogram = new Uint32Array(256);
    gray.forEach(value => { histogram[value] += 1; });
    let totalSum = 0;
    for (let value = 0; value < 256; value += 1) totalSum += value * histogram[value];
    let backgroundWeight = 0;
    let backgroundSum = 0;
    let bestVariance = -1;
    let threshold = 128;
    for (let value = 0; value < 256; value += 1) {
      backgroundWeight += histogram[value];
      if (!backgroundWeight) continue;
      const foregroundWeight = gray.length - backgroundWeight;
      if (!foregroundWeight) break;
      backgroundSum += value * histogram[value];
      const backgroundMean = backgroundSum / backgroundWeight;
      const foregroundMean = (totalSum - backgroundSum) / foregroundWeight;
      const variance = backgroundWeight * foregroundWeight * (backgroundMean - foregroundMean) ** 2;
      if (variance > bestVariance) {
        bestVariance = variance;
        threshold = value;
      }
    }
    return threshold;
  }

  function imageToBinary(imageData) {
    const gray = new Uint8Array(imageData.width * imageData.height);
    for (let pixel = 0, offset = 0; pixel < gray.length; pixel += 1, offset += 4) {
      gray[pixel] = Math.round(imageData.data[offset] * 0.299 + imageData.data[offset + 1] * 0.587 + imageData.data[offset + 2] * 0.114);
    }
    const threshold = otsuThreshold(gray);
    return { pixels: Uint8Array.from(gray, value => value <= threshold ? 1 : 0), width: imageData.width, height: imageData.height };
  }

  function finderRatio(runs) {
    const total = runs.reduce((sum, value) => sum + value, 0);
    if (total < 14) return 0;
    const module = total / 7;
    const tolerance = module * 0.72;
    const expected = [module, module, module * 3, module, module];
    return runs.every((value, index) => Math.abs(value - expected[index]) <= (index === 2 ? tolerance * 1.5 : tolerance)) ? module : 0;
  }

  function scanLines(binary, horizontal) {
    const { pixels, width, height } = binary;
    const lineCount = horizontal ? height : width;
    const lineLength = horizontal ? width : height;
    const candidates = [];
    for (let line = 0; line < lineCount; line += 1) {
      const runs = [];
      let color = 0;
      let length = 0;
      for (let position = 0; position <= lineLength; position += 1) {
        const next = position < lineLength ? pixels[horizontal ? line * width + position : position * width + line] : -1;
        if (next === color) {
          length += 1;
          continue;
        }
        if (length) runs.push({ color, length, end: position });
        color = next;
        length = 1;
      }
      for (let index = 0; index <= runs.length - 5; index += 1) {
        const group = runs.slice(index, index + 5);
        if (group.some((run, offset) => run.color !== (offset % 2 === 0 ? 1 : 0))) continue;
        const module = finderRatio(group.map(run => run.length));
        if (!module) continue;
        const center = group[2].end - group[2].length / 2;
        candidates.push(horizontal ? { x: center, y: line, module } : { x: line, y: center, module });
      }
    }
    return candidates;
  }

  function finderCenters(binary) {
    const rows = scanLines(binary, true);
    const columns = scanLines(binary, false);
    const intersections = [];
    rows.forEach(row => {
      columns.forEach(column => {
        const scale = Math.max(row.module, column.module);
        if (Math.abs(row.x - column.x) <= scale * 1.8 && Math.abs(row.y - column.y) <= scale * 1.8) {
          intersections.push({ x: (row.x + column.x) / 2, y: (row.y + column.y) / 2, module: (row.module + column.module) / 2 });
        }
      });
    });
    const clusters = [];
    intersections.forEach(point => {
      const cluster = clusters.find(item => Math.hypot(item.x - point.x, item.y - point.y) <= Math.max(item.module, point.module) * 2.5);
      if (cluster) {
        cluster.count += 1;
        const weight = 1 / cluster.count;
        cluster.x += (point.x - cluster.x) * weight;
        cluster.y += (point.y - cluster.y) * weight;
        cluster.module += (point.module - cluster.module) * weight;
      } else {
        clusters.push({ ...point, count: 1 });
      }
    });
    return clusters.filter(item => item.count >= 2).sort((a, b) => b.count - a.count).slice(0, 12);
  }

  function selectFinderTriangle(centers) {
    let best = null;
    for (let pivotIndex = 0; pivotIndex < centers.length; pivotIndex += 1) {
      for (let firstIndex = 0; firstIndex < centers.length; firstIndex += 1) {
        if (firstIndex === pivotIndex) continue;
        for (let secondIndex = firstIndex + 1; secondIndex < centers.length; secondIndex += 1) {
          if (secondIndex === pivotIndex) continue;
          const pivot = centers[pivotIndex];
          const first = centers[firstIndex];
          const second = centers[secondIndex];
          const ax = first.x - pivot.x;
          const ay = first.y - pivot.y;
          const bx = second.x - pivot.x;
          const by = second.y - pivot.y;
          const aLength = Math.hypot(ax, ay);
          const bLength = Math.hypot(bx, by);
          if (Math.min(aLength, bLength) < Math.max(pivot.module, 2) * 15) continue;
          const rightness = Math.abs((ax * bx + ay * by) / (aLength * bLength));
          const balance = Math.min(aLength, bLength) / Math.max(aLength, bLength);
          if (rightness > 0.36 || balance < 0.48) continue;
          const score = pivot.count + first.count + second.count + balance * 8 - rightness * 10;
          if (!best || score > best.score) best = { pivot, first, second, ax, ay, bx, by, score };
        }
      }
    }
    if (!best) throw new Error("GoblinPass QR finder pattern was not detected.");
    const cross = best.ax * best.by - best.ay * best.bx;
    return cross > 0
      ? { topLeft: best.pivot, topRight: best.first, bottomLeft: best.second }
      : { topLeft: best.pivot, topRight: best.second, bottomLeft: best.first };
  }

  function sampleModules(binary, triangle) {
    const { pixels, width, height } = binary;
    const xAxis = { x: (triangle.topRight.x - triangle.topLeft.x) / 26, y: (triangle.topRight.y - triangle.topLeft.y) / 26 };
    const yAxis = { x: (triangle.bottomLeft.x - triangle.topLeft.x) / 26, y: (triangle.bottomLeft.y - triangle.topLeft.y) / 26 };
    return Array.from({ length: SIZE }, (_, y) => Array.from({ length: SIZE }, (_, x) => {
      const centerX = triangle.topLeft.x + (x - 3) * xAxis.x + (y - 3) * yAxis.x;
      const centerY = triangle.topLeft.y + (x - 3) * xAxis.y + (y - 3) * yAxis.y;
      let dark = 0;
      let samples = 0;
      for (let offsetY = -1; offsetY <= 1; offsetY += 1) {
        for (let offsetX = -1; offsetX <= 1; offsetX += 1) {
          const sampleX = Math.round(centerX + offsetX * xAxis.x * 0.16 + offsetY * yAxis.x * 0.16);
          const sampleY = Math.round(centerY + offsetX * xAxis.y * 0.16 + offsetY * yAxis.y * 0.16);
          if (sampleX < 0 || sampleY < 0 || sampleX >= width || sampleY >= height) continue;
          dark += pixels[sampleY * width + sampleX];
          samples += 1;
        }
      }
      return samples > 0 && dark * 2 >= samples;
    }));
  }

  function decodeImageData(imageData) {
    const binary = imageToBinary(imageData);
    const triangle = selectFinderTriangle(finderCenters(binary));
    return decodeModules(sampleModules(binary, triangle));
  }

  async function detect(source) {
    const sourceWidth = source.videoWidth || source.naturalWidth || source.width;
    const sourceHeight = source.videoHeight || source.naturalHeight || source.height;
    if (!sourceWidth || !sourceHeight) return "";
    const scale = Math.min(1, 720 / Math.max(sourceWidth, sourceHeight));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(sourceWidth * scale));
    canvas.height = Math.max(1, Math.round(sourceHeight * scale));
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(source, 0, 0, canvas.width, canvas.height);
    return decodeImageData(context.getImageData(0, 0, canvas.width, canvas.height));
  }

  return { decodeImageData, decodeModules, detect };
});
