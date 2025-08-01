import { p256 } from '@noble/curves/p256'

export const compressPubkey = (pubkeyBytes: Uint8Array): Uint8Array => {
  const point = p256.ProjectivePoint.fromHex(pubkeyBytes)
  return point.toRawBytes(true)
}

export const decompressPubkey = (compressed: Uint8Array): Uint8Array => {
  if (compressed.length !== 33) {
    throw new Error('Expected 33 byte compress pubkey')
  }
  const point = p256.ProjectivePoint.fromHex(compressed)
  return point.toRawBytes(false)
}
