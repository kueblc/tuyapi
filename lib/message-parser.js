const debug = require('debug')('TuyAPI:MessageParser');
const crc = require('./crc');

const HEADER_SIZE = 16;

/**
* Parse a packet from a device into a
* payload and command type
* @param {Buffer} data packet to parse
* @returns {Object} result
* @returns {String|Buffer|Object} result.data decoded data, if available in response
* @returns {Number} result.commandByte command byte from decoded data
*/
function parse(data) {
  // Check for length
  // At minimum requires: prefix (4), sequence (4), command (4), length (4),
  // CRC (4), and suffix (4) for 24 total bytes
  // Messages from the device also include return code (4), for 28 total bytes
  if (data.length < 24) {
    throw new Error('Packet too small. Length: ' + data.length);
  }

  // Check for prefix
  const prefix = data.readUInt32BE(0);

  if (prefix !== 0x000055AA) {
    throw new Error('Magic prefix mismatch: ' + data.toString('hex'));
  }

  // Get the command type
  const commandByte = data.readUInt32BE(8);

  // Get payload size
  const payloadSize = data.readUInt32BE(12);

  // Check for payload
  if (data.length < HEADER_SIZE + payloadSize) {
    throw new Error('Packet missing payload: ' + data.toString('hex'));
  }

  // Get the return code, 0 = success
  // This field is only present in messages from the devices
  // Absent in messages sent to device
  const returnCode = data.readUInt32BE(16);

  // Get the payload
  // Adjust for messages lacking a return code
  let payload;
  if (returnCode & 0xFFFFFF00) {
    payload = data.slice(HEADER_SIZE, HEADER_SIZE + payloadSize - 8);
  } else {
    payload = data.slice(HEADER_SIZE + 4, HEADER_SIZE + payloadSize - 8);
  }

  // Check CRC
  const expectedCrc = data.readInt32BE(HEADER_SIZE + payloadSize - 8);
  const computedCrc = crc(data.slice(0, payloadSize + 8));

  if (expectedCrc !== computedCrc) {
    throw new Error('CRC mismatch: ' + data.toString('hex'));
  }

  // Check for suffix
  const suffix = data.readUInt32BE(HEADER_SIZE + payloadSize - 4);

  if (suffix !== 0x0000AA55) {
    throw new Error('Magic suffix mismatch: ' + data.toString('hex'));
  }

  // Check for leftovers
  if (data.length > HEADER_SIZE + payloadSize) {
    debug(data.length - HEADER_SIZE - payloadSize, 'bytes left over');
    // Skip the leftovers for now
  }

  // Attempt to parse data to JSON.
  const result = {
    commandByte
  };
  // It's possible for packets to be valid
  // and yet contain no data.
  if (payload.length === 0) {
    return result;
  }

  // Try to parse data as JSON.
  // If error, return as string.
  try {
    result.data = JSON.parse(payload);
  } catch (error) { // Data is encrypted
    result.data = payload.toString('ascii');
  }

  return result;
}

/**
* Encode data (usually an object) into
* a protocol-compliant form that a device
* can understand.
* @param {Object} options
* @param {String|Buffer|Object} options.data data to encode
* @param {Number} options.commandByte command byte
* @returns {Buffer} binary payload
*/
function encode(options) {
  // Ensure data is a Buffer
  let payload;

  if (options.data instanceof Buffer) {
    payload = options.data;
  } else {
    if (typeof options.data === 'string') {
      payload = options.data;
    } else {
      payload = JSON.stringify(options.data);
    }

    payload = Buffer.from(payload);
  }

  // Ensure commandByte is a Number
  if (typeof options.commandByte === 'string') {
    options.commandByte = parseInt(options.commandByte, 16);
  }

  // Allocate buffer with room for payload + 24 bytes for
  // prefix, sequence, command, length, crc, and suffix
  const buffer = Buffer.alloc(payload.length + 24);

  // Add prefix, command, and length
  // Skip sequence number, currently not used
  buffer.writeUInt32BE(0x000055AA, 0);
  buffer.writeUInt32BE(options.commandByte, 8);
  buffer.writeUInt32BE(payload.length + 8, 12);

  // Add payload, crc, and suffix
  payload.copy(buffer, 16);
  buffer.writeInt32BE(crc(buffer.slice(0, payload.length + 16)), payload.length + 16);
  buffer.writeUInt32BE(0x0000AA55, payload.length + 20);

  return buffer;
}

module.exports = {parse, encode};
