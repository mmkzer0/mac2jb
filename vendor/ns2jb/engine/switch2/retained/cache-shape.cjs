// Some acquisitions leave the known UAF pathname in unused cache entries.
// Reject every other nonzero tail; it could own real cached buffers.
function unusedTail(bytes) {
  if (bytes.length !== 0x5a0) return false;
  const tail = bytes.subarray(0x30);
  if (!tail.some(Boolean)) return true;
  let start;
  let exactEightBytePath = false;
  if (tail[0] === 0x41) start = 0;
  else if (tail[0] === 0 && tail[1] === 0x41) start = 1;
  else if (tail.subarray(0, 8).toString('hex') === '0000400100000000') {
    start = 8;
    exactEightBytePath = true;
  }
  else if (tail.subarray(0, 5).toString('hex') === '0000400100')
    start = tail[5] === 0 ? 6 : 5;
  else return false;
  const text = tail.subarray(start), end = text.indexOf(0);
  return end > 0 && (!exactEightBytePath || end === 552) &&
    text.subarray(0, end).every(b => b === 0x41 || b === 0x2f) &&
    text.subarray(0, end).includes(0x2f) && !text.subarray(end).some(Boolean);
}
module.exports = {unusedTail, decodeSlotInventory, summarizeOccupancy};

// Raw decode of a captured cache array: ten 0x90 buckets of three 0x30 slots.
// Pure function so the layout can be unit-tested without a console.
function decodeSlotInventory(bytes) {
  if (bytes.length % 0x90 !== 0) throw Error('Cache array is not a whole number of 0x90 buckets');
  const buckets = bytes.length / 0x90;
  const slots = [];
  for (let bucket = 0; bucket < buckets; bucket++) {
    for (let slot = 0; slot < 3; slot++) {
      const at = bucket * 0x90 + slot * 0x30;
      slots.push({
        bucket, slot,
        offset: bytes.readBigUInt64LE(at).toString(),
        size: bytes.readBigUInt64LE(at + 8).toString(),
        valid: bytes[at + 0x10], writeBack: bytes[at + 0x11],
        cached: bytes[at + 0x12], flushing: bytes[at + 0x13],
        handle: bytes.readBigUInt64LE(at + 0x18).toString(),
        address: bytes.readBigUInt64LE(at + 0x20).toString(),
        memorySize: bytes.readBigUInt64LE(at + 0x28).toString()
      });
    }
  }
  return slots;
}

function summarizeOccupancy(slots) {
  const buckets = new Map();
  for (const slot of slots) {
    if (!buckets.has(slot.bucket)) buckets.set(slot.bucket, {bucket: slot.bucket, validSlots: 0, cachedSlots: 0, cachedValidSlots: 0});
    const entry = buckets.get(slot.bucket);
    if (slot.valid === 1) entry.validSlots++;
    if (slot.cached === 1) entry.cachedSlots++;
    if (slot.valid === 1 && slot.cached === 1) entry.cachedValidSlots++;
  }
  return [...buckets.values()];
}
