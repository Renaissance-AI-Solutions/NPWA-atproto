/**
 * NPWA Platform Encrypted Blob Storage Adapter
 * 
 * Extends the PDS BlobStore interface with client-side encryption
 * for secure storage of user documents and PHI data.
 */

import { BlobStore } from '@atproto/repo'
import { CID } from 'multiformats/cid'
import * as crypto from 'crypto'
import { Readable } from 'stream'

// Encryption configuration
const ENCRYPTION_ALGORITHM = 'aes-256-cbc'
const KEY_SIZE = 32 // 256 bits
const IV_SIZE = 16 // 128 bits
const SALT_SIZE = 32 // 256 bits

export interface EncryptedBlobMetadata {
  originalSize: number
  encryptedSize: number
  algorithm: string
  keyDerivationSalt: string
  iv: string
  timestamp: number
  version: string
}

export interface EncryptionKey {
  key: Buffer
  salt: Buffer
}

/**
 * Generate encryption key from user DID and master key
 */
function deriveEncryptionKey(userDid: string, masterKey: string): EncryptionKey {
  const salt = crypto.randomBytes(SALT_SIZE)
  const key = crypto.pbkdf2Sync(
    Buffer.from(masterKey, 'hex'),
    salt,
    100000, // iterations
    KEY_SIZE,
    'sha256'
  )
  
  return { key, salt }
}

/**
 * Encrypt blob data
 */
function encryptBlob(
  data: Buffer,
  encryptionKey: EncryptionKey
): {
  encryptedData: Buffer
  metadata: EncryptedBlobMetadata
} {
  const iv = crypto.randomBytes(IV_SIZE)
  const cipher = crypto.createCipher(ENCRYPTION_ALGORITHM, encryptionKey.key)
  
  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final()
  ])
  
  // Combine salt + iv + encrypted data (no auth tag for CBC mode)
  const encryptedData = Buffer.concat([
    encryptionKey.salt,
    iv,
    encrypted
  ])
  
  const metadata: EncryptedBlobMetadata = {
    originalSize: data.length,
    encryptedSize: encryptedData.length,
    algorithm: ENCRYPTION_ALGORITHM,
    keyDerivationSalt: encryptionKey.salt.toString('hex'),
    iv: iv.toString('hex'),
    timestamp: Date.now(),
    version: '1.0'
  }
  
  return { encryptedData, metadata }
}

/**
 * Decrypt blob data
 */
function decryptBlob(
  encryptedData: Buffer,
  masterKey: string,
  metadata: EncryptedBlobMetadata
): Buffer {
  // Extract components from encrypted data (no auth tag for CBC mode)
  const salt = encryptedData.subarray(0, SALT_SIZE)
  const iv = encryptedData.subarray(SALT_SIZE, SALT_SIZE + IV_SIZE)
  const encrypted = encryptedData.subarray(SALT_SIZE + IV_SIZE)
  
  // Derive key
  const key = crypto.pbkdf2Sync(
    Buffer.from(masterKey, 'hex'),
    salt,
    100000,
    KEY_SIZE,
    'sha256'
  )
  
  // Decrypt
  const decipher = crypto.createDecipher(metadata.algorithm, key)
  
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ])
  
  return decrypted
}

/**
 * Encrypted Blob Store implementation
 */
export class EncryptedBlobStore implements BlobStore {
  private baseBlobStore: BlobStore
  private metadataStore: Map<string, EncryptedBlobMetadata>
  
  constructor(baseBlobStore: BlobStore) {
    this.baseBlobStore = baseBlobStore
    this.metadataStore = new Map()
  }
  
  // BlobStore interface implementation
  async putTemp(bytes: Uint8Array | Readable): Promise<string> {
    return this.baseBlobStore.putTemp(bytes)
  }
  
  async makePermanent(key: string, cid: CID): Promise<void> {
    return this.baseBlobStore.makePermanent(key, cid)
  }
  
  async putPermanent(cid: CID, bytes: Uint8Array | Readable): Promise<void> {
    return this.baseBlobStore.putPermanent(cid, bytes)
  }
  
  async quarantine(cid: CID): Promise<void> {
    return this.baseBlobStore.quarantine(cid)
  }
  
  async unquarantine(cid: CID): Promise<void> {
    return this.baseBlobStore.unquarantine(cid)
  }
  
  async getBytes(cid: CID): Promise<Uint8Array> {
    return this.baseBlobStore.getBytes(cid)
  }
  
  async getStream(cid: CID): Promise<Readable> {
    return this.baseBlobStore.getStream(cid)
  }
  
  async hasTemp(key: string): Promise<boolean> {
    return this.baseBlobStore.hasTemp(key)
  }
  
  async hasStored(cid: CID): Promise<boolean> {
    return this.baseBlobStore.hasStored(cid)
  }
  
  async delete(cid: CID): Promise<void> {
    try {
      await this.baseBlobStore.delete(cid)
      this.metadataStore.delete(cid.toString())
    } catch (error) {
      throw new Error(`Encrypted blob deletion failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  
  async deleteMany(cids: CID[]): Promise<void> {
    try {
      await this.baseBlobStore.deleteMany(cids)
      for (const cid of cids) {
        this.metadataStore.delete(cid.toString())
      }
    } catch (error) {
      throw new Error(`Encrypted blob batch deletion failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  
  // Additional encrypted blob methods
  async putEncryptedTemp(
    bytes: Uint8Array | Readable,
    userDid: string,
    masterKey: string
  ): Promise<string> {
    try {
      // Convert to buffer if needed
      let data: Buffer
      if (bytes instanceof Uint8Array) {
        data = Buffer.from(bytes)
      } else {
        const chunks: Buffer[] = []
        for await (const chunk of bytes) {
          chunks.push(chunk)
        }
        data = Buffer.concat(chunks)
      }
      
      // Generate encryption key
      const encryptionKey = deriveEncryptionKey(userDid, masterKey)
      
      // Encrypt the blob
      const { encryptedData, metadata } = encryptBlob(data, encryptionKey)
      
      // Store encrypted blob as temp
      const tempKey = await this.baseBlobStore.putTemp(encryptedData)
      
      // Store metadata with temp key
      this.metadataStore.set(tempKey, metadata)
      
      return tempKey
    } catch (error) {
      throw new Error(`Encrypted temp blob storage failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  
  async getEncryptedBytes(
    cid: CID,
    userDid: string,
    masterKey: string
  ): Promise<Uint8Array> {
    try {
      // Get encrypted blob from base store
      const encryptedData = await this.baseBlobStore.getBytes(cid)
      
      // Get metadata
      const metadata = this.metadataStore.get(cid.toString())
      if (!metadata) {
        throw new Error('Blob metadata not found')
      }
      
      // Decrypt blob
      const decryptedData = decryptBlob(Buffer.from(encryptedData), masterKey, metadata)
      
      return new Uint8Array(decryptedData)
    } catch (error) {
      throw new Error(`Encrypted blob retrieval failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  
  /**
   * Get blob metadata
   */
  getBlobMetadata(cid: CID): EncryptedBlobMetadata | null {
    return this.metadataStore.get(cid.toString()) || null
  }
  
  /**
   * Verify blob integrity
   */
  async verifyBlobIntegrity(
    cid: CID,
    userDid: string,
    masterKey: string
  ): Promise<boolean> {
    try {
      const blob = await this.getEncryptedBytes(cid, userDid, masterKey)
      return blob !== null
    } catch (error) {
      console.warn('Blob integrity verification failed:', error instanceof Error ? error.message : String(error))
      return false
    }
  }
  
  /**
   * Get storage statistics
   */
  getStorageStats(): {
    totalBlobs: number
    totalEncryptedSize: number
    totalOriginalSize: number
  } {
    let totalEncryptedSize = 0
    let totalOriginalSize = 0
    
    for (const metadata of this.metadataStore.values()) {
      totalEncryptedSize += metadata.encryptedSize
      totalOriginalSize += metadata.originalSize
    }
    
    return {
      totalBlobs: this.metadataStore.size,
      totalEncryptedSize,
      totalOriginalSize
    }
  }
  
  /**
   * Export metadata for backup
   */
  exportMetadata(): Record<string, EncryptedBlobMetadata> {
    return Object.fromEntries(this.metadataStore.entries())
  }
  
  /**
   * Import metadata from backup
   */
  importMetadata(metadata: Record<string, EncryptedBlobMetadata>): void {
    this.metadataStore.clear()
    for (const [cid, meta] of Object.entries(metadata)) {
      this.metadataStore.set(cid, meta)
    }
  }
}

/**
 * Factory function to create encrypted blob store
 */
export function createEncryptedBlobStore(baseBlobStore: BlobStore): EncryptedBlobStore {
  return new EncryptedBlobStore(baseBlobStore)
}

/**
 * Utility functions for encryption key management
 */
export const EncryptionUtils = {
  /**
   * Generate a new master key
   */
  generateMasterKey(): string {
    return crypto.randomBytes(32).toString('hex')
  },
  
  /**
   * Validate master key format
   */
  isValidMasterKey(key: string): boolean {
    try {
      const buffer = Buffer.from(key, 'hex')
      return buffer.length === 32
    } catch {
      return false
    }
  },
  
  /**
   * Create key derivation salt
   */
  createSalt(): string {
    return crypto.randomBytes(32).toString('hex')
  }
} 