import * as crypto from "crypto";
import * as asn1 from "asn1";
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

  private csrDefineEncoded() {
    const writer = new asn1.BerWriter();
    writer.startSequence();
    writer.writeInt(0); // version
    writer.startSequence(); // subject

    writer.startSequence();
    writer.writeOID("2.5.4.6", asn1.Ber.OID);
    writer.writeString(
      this.certificateDN.countryName,
      asn1.Ber.PrintableString
    );
    writer.endSequence();

    writer.startSequence();
    writer.writeOID("2.5.4.8", asn1.Ber.OID);
    writer.writeString(
      this.certificateDN.stateOrProvinceName,
      asn1.Ber.PrintableString
    );
    writer.endSequence();

    writer.startSequence();
    writer.writeOID("2.5.4.7", asn1.Ber.OID);
    writer.writeString(
      this.certificateDN.localityName,
      asn1.Ber.PrintableString
    );
    writer.endSequence();

    writer.startSequence();
    writer.writeOID("2.5.4.10", asn1.Ber.OID);
    writer.writeString(
      this.certificateDN.organizationName,
      asn1.Ber.PrintableString
    );
    writer.endSequence();

    if (this.certificateDN.organizationalUnitName) {
      writer.startSequence();
      writer.writeOID("2.5.4.11", asn1.Ber.OID);
      writer.writeString(
        this.certificateDN.organizationalUnitName,
        asn1.Ber.PrintableString
      );
      writer.endSequence();
    }

    writer.startSequence();
    writer.writeOID("2.5.4.3", asn1.Ber.OID);
    writer.writeString(this.certificateDN.commonName, asn1.Ber.IA5String);
    writer.endSequence();

    if (this.certificateDN.emailAddress) {
      writer.startSequence();
      writer.writeOID("1.2.840.113549.1.9.1", asn1.Ber.OID);
      writer.writeString(this.certificateDN.emailAddress, asn1.Ber.IA5String);
      writer.endSequence();
    }
    writer.endSequence(); // end of subject
    // SubjectPKInfo
    writer.startSequence();
    writer.startSequence(); //start algo
    writer.writeOID("1.2.840.10045.2.1", asn1.Ber.OID); // ecPublicKey
    writer.writeOID("1.3.132.0.10", asn1.Ber.OID); // secp256k1
    writer.endSequence(); //end of algot
    writer.writeBuffer(
      Buffer.from(
        this.keyPairs.publicKey.replace(
          /-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g,
          ""
        ),
        "base64"
      ),
      asn1.Ber.BitString
    );
    writer.endSequence(); // End of SubjectPKInfo

    writer.startSequence(asn1.Ber.Constructor | asn1.Ber.Context);
    writer.endSequence(); // End of Attributes
    
    writer.endSequence(); // End of CSRInfo

    const csrInfoEncoded = writer.buffer;
    this.csrInfoEncoded = csrInfoEncoded;
    return csrInfoEncoded;
  }
  private sign() {
    const sign = crypto.createSign("SHA256");
    this.csrDefineEncoded();

    sign.update(this.csrInfoEncoded);

    const signature = sign.sign(this.keyPairs.privateKey);
    this.signature = signature;
    return signature;
  }
  exportCsr() {
    this.sign();
    const finalWriter = new asn1.BerWriter();
    finalWriter.startSequence(); // Start of CSR
    //finalWriter.writeBuffer(this.csrInfoEncoded,asn1.Ber.Sequence); // Write CSRInfo as a Sequence
    finalWriter._ensure(this.csrInfoEncoded.length);
    this.csrInfoEncoded.copy(
      finalWriter._buf,
      finalWriter._offset,
      0,
      this.csrInfoEncoded.length
    );
    finalWriter._offset += this.csrInfoEncoded.length;
    finalWriter.startSequence();
    finalWriter.writeOID("1.2.840.10045.4.3.2", asn1.Ber.OID); // ecdsa-with-SHA256
    finalWriter.endSequence();

    // Signature
    finalWriter.writeBuffer(this.signature, asn1.Ber.BitString);
    finalWriter.endSequence();
    const finalCsr = finalWriter.buffer;
    console.log(finalCsr.toString("base64"), " hi");

    if (!finalCsr) {
      throw new Error("Failed to generate CSR.");
    }
    const pemCsr = `-----BEGIN CERTIFICATE REQUEST-----\n${finalCsr
      .toString("base64")
      .match(/.{1,64}/g)
      ?.join("\n")}\n-----END CERTIFICATE REQUEST-----\n`;

    return pemCsr;
  }
}
