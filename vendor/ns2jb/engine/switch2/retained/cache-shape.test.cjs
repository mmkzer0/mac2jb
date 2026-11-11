'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {unusedTail} = require('./cache-shape.cjs');

test('accepts only the observed eight-byte prefix and 552-byte path shape', () => {
  const bytes = Buffer.alloc(0x5a0);
  const tail = bytes.subarray(0x30);
  Buffer.from('0000400100000000', 'hex').copy(tail);
  tail.fill(0x41, 8, 8 + 552);
  tail[20] = 0x2f;
  assert.equal(unusedTail(bytes), true);

  const wrongLength = Buffer.from(bytes);
  wrongLength[0x30 + 8 + 551] = 0;
  assert.equal(unusedTail(wrongLength), false);

  const wrongPrefix = Buffer.from(bytes);
  wrongPrefix[0x30 + 2] = 0x41;
  assert.equal(unusedTail(wrongPrefix), false);
});

const {decodeSlotInventory, summarizeOccupancy} = require('./cache-shape.cjs');

test('decodes ten buckets of three 0x30 slots with a 64-bit handle', () => {
  const bytes = Buffer.alloc(0x5a0);
  // bucket 0 slot 0: valid + cached, range 0..0x4000, 64-bit handle with high word
  bytes.writeBigUInt64LE(0n, 0x00);
  bytes.writeBigUInt64LE(0x4000n, 0x08);
  bytes[0x10] = 1; bytes[0x12] = 1;
  bytes.writeBigUInt64LE(0x0000000100000002n, 0x18);
  bytes.writeBigUInt64LE(0x1000n, 0x20);
  bytes.writeBigUInt64LE(0x4000n, 0x28);
  // bucket 0 slot 2: valid, not cached (bypasses the buffer)
  bytes[0x60 + 0x10] = 1;
  // bucket 3 slot 1: valid + cached
  bytes[3 * 0x90 + 0x30 + 0x10] = 1; bytes[3 * 0x90 + 0x30 + 0x12] = 1;

  const slots = decodeSlotInventory(bytes);
  assert.equal(slots.length, 30);
  assert.deepEqual(slots[0], {
    bucket: 0, slot: 0, offset: '0', size: '16384', valid: 1, writeBack: 0,
    cached: 1, flushing: 0, handle: '4294967298', address: '4096', memorySize: '16384'
  });
  assert.equal(slots[2].valid, 1);
  assert.equal(slots[2].cached, 0);
  assert.equal(slots[3 * 3 + 1].valid, 1);
  assert.equal(slots[3 * 3 + 1].cached, 1);

  const occupancy = summarizeOccupancy(slots);
  assert.equal(occupancy.length, 10);
  assert.deepEqual(occupancy[0], {bucket: 0, validSlots: 2, cachedSlots: 1, cachedValidSlots: 1});
  assert.deepEqual(occupancy[3], {bucket: 3, validSlots: 1, cachedSlots: 1, cachedValidSlots: 1});
  assert.deepEqual(occupancy[1], {bucket: 1, validSlots: 0, cachedSlots: 0, cachedValidSlots: 0});
  assert.throws(() => decodeSlotInventory(Buffer.alloc(0x5a1)), /whole number of 0x90 buckets/);
});
