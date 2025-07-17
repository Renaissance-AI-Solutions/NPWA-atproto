import crypto from 'node:crypto'
import * as ui8 from 'uint8arrays'
import { sha256 } from '@atproto/crypto'

export const OLD_PASSWORD_MAX_LENGTH = 512
export const NEW_PASSWORD_MAX_LENGTH = 256

export const genSaltAndHash = (password: string): Promise<string> => {
  console.log('=== GENERATING SALT AND HASH DEBUG START ===');
  console.log('Password to hash:', password);

  const salt = crypto.randomBytes(16).toString('hex')
  console.log('Generated salt:', salt);

  const hashPromise = hashWithSalt(password, salt);
  hashPromise.then(result => {
    console.log('Generated hash result:', result);
    console.log('=== GENERATING SALT AND HASH DEBUG END ===');
  });

  return hashPromise;
}

export const hashWithSalt = (
  password: string,
  salt: string,
): Promise<string> => {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, hash) => {
      if (err) return reject(err)
      resolve(salt + ':' + hash.toString('hex'))
    })
  })
}

export const verify = async (
  password: string,
  storedHash: string,
): Promise<boolean> => {
  console.log('=== SCRYPT VERIFICATION DEBUG START ===');
  console.log('Password to verify:', password);
  console.log('Stored hash:', storedHash);

  if (!storedHash || storedHash === '') {
    console.log('ERROR: storedHash is empty or null');
    return false;
  }

  const parts = storedHash.split(':');
  console.log('Hash parts after split:', parts);
  console.log('Number of parts:', parts.length);

  if (parts.length !== 2) {
    console.log('ERROR: Invalid hash format - should have exactly 2 parts separated by ":"');
    return false;
  }

  const [salt, hash] = parts;
  console.log('Salt:', salt);
  console.log('Hash:', hash);

  if (!salt || !hash) {
    console.log('ERROR: Salt or hash is empty');
    return false;
  }

  console.log('Deriving hash from password and salt...');
  const derivedHash = await getDerivedHash(password, salt);
  console.log('Derived hash:', derivedHash);

  const result = hash === derivedHash;
  console.log('Hash comparison result:', result);
  console.log('=== SCRYPT VERIFICATION DEBUG END ===');

  return result;
}

export const getDerivedHash = (
  password: string,
  salt: string,
): Promise<string> => {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedHash) => {
      if (err) return reject(err)
      resolve(derivedHash.toString('hex'))
    })
  })
}

export const hashAppPassword = async (
  did: string,
  password: string,
): Promise<string> => {
  const sha = await sha256(did)
  const salt = ui8.toString(sha.slice(0, 16), 'hex')
  return hashWithSalt(password, salt)
}
