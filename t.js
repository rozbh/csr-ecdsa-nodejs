const asn1 = require('asn1');

// Create an ASN.1 writer for the inner sequence
const innerWriter = new asn1.BerWriter();

// Create the inner sequence
innerWriter.startSequence();
innerWriter.writeInt(123);
innerWriter.writeString('Hello');
innerWriter.endSequence();

// Save the encoded inner sequence
const innerSequence = innerWriter.buffer;

// Create an ASN.1 writer for the outer sequence
const outerWriter = new asn1.BerWriter();

// Create the outer sequence
outerWriter.startSequence();

// Add the inner sequence directly into the outer sequence
outerWriter._ensure(innerSequence.length);
innerSequence.copy(outerWriter._buf, outerWriter._offset, 0, innerSequence.length);
outerWriter._offset += innerSequence.length;

// Add more elements to the outer sequence if needed
outerWriter.writeString('World');

outerWriter.endSequence();

// Get the final encoded sequence
const outerSequence = outerWriter.buffer;

console.log('Inner Sequence:', innerSequence.toString('hex'));
console.log('Outer Sequence:', outerSequence.toString('base64'));
