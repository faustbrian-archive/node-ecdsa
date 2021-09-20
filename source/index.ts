import { secp256k1 } from "bcrypto";

export const sign = (hash: string, privateKey: string): string =>
  secp256k1.signatureExport(
    secp256k1.sign(Buffer.from(hash, "hex"), Buffer.from(privateKey, "hex")),
  ).toString("hex");

export const verify = (
  hash: string,
  signature: string,
  publicKey: string,
): boolean =>
  secp256k1.verify(
    Buffer.from(hash, "hex"),
    secp256k1.signatureImport(Buffer.from(signature, "hex")),
    Buffer.from(publicKey, "hex"),
  );

export const verifyBatch = (hashes: {
  hash: string;
  signature: string;
  publicKey: string;
}[]): boolean => {
  for (const hash of hashes) {
    if (verify(hash.hash, hash.signature, hash.publicKey)) {
      continue;
    }

    return false;
  }

  return true;
};
