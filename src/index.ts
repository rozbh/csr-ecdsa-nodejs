import { EcdsaCsrGenerator } from './utils/CSR.class';
const subject = {
  countryName: "US", // C
  stateOrProvinceName: "California", // ST
  localityName: "San Francisco", // L
  organizationName: "My Company", // O
  organizationalUnitName: "IT Department", // OU (optional)
  commonName: "www.example.com", // CN
  emailAddress: "admin@example.com", // emailAddress (optional)
};
const x = new EcdsaCsrGenerator(subject).exportCsr();
import fs from 'fs'

fs.writeFileSync('test.csr',x)
console.log(Buffer.from(x).toString('base64'));
