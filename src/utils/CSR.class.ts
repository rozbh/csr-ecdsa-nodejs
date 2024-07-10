import * as crypto from "crypto";
import * as x509 from "@peculiar/x509";
type KeyPairs = { publicKey: string; privateKey: string };

type CertificateDN = {
  countryName: string; // C
  stateOrProvinceName: string; // ST
  localityName: string; // L
  organizationName: string; // O
  organizationalUnitName?: string; // OU (optional)
  commonName: string; // CN
  emailAddress?: string; // emailAddress (optional)
};
export class EcdsaCsrGenerator {
  private keyPairs: KeyPairs;
  private certificateDN: CertificateDN;
  private csrInfoEncoded: Buffer;
  private signature: Buffer;
  constructor(certificateDN: CertificateDN) {
    this.csrInfoEncoded = Buffer.from("");
    this.signature = Buffer.from("");
    this.certificateDN = certificateDN;
    this.keyPairs = this.generateKeyPairs();
  }
  private generateKeyPairs = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });
    return { publicKey, privateKey };
  };
  private temp() {
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Test",
      notBefore: new Date("2020/01/01"),
      notAfter: new Date("2020/01/02"),
      signingAlgorithm: alg,
      keys: this.keyPairs,
      extensions: [
        new x509.BasicConstraintsExtension(true, 2, true),
        new x509.ExtendedKeyUsageExtension(
          ["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"],
          true
        ),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true
        ),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });

    console.log(cert.toString("pem")); // Certificate in PEM format
  }
}
