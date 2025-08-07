/**
 * Performance and Load Testing for Journal System
 * 
 * Validates system performance under various load conditions,
 * encryption/decryption performance, and memory usage patterns.
 */

import { AtpAgent } from '@atproto/api'
import { TestNetworkNoAppView } from '@atproto/dev-env'
import { TID } from '@atproto/common'
import { AtUri } from '@atproto/syntax'
import {
  PrivacyLevel,
  SecurityClassification,
  EncryptionLevel,
  SecurityContext,
  PrivacyAccessControlManager,
  HIPAAComplianceManager,
  EncryptionManager,
} from '../../src/journal-security'
import { AppContext } from '../../src/context'

// Performance test configuration
const PERFORMANCE_THRESHOLDS = {
  SINGLE_ENTRY_CREATE: 1000, // 1 second
  SINGLE_ENTRY_READ: 200, // 200ms
  SINGLE_ENTRY_UPDATE: 500, // 500ms
  SINGLE_ENTRY_DELETE: 300, // 300ms
  BATCH_CREATE_100: 10000, // 10 seconds for 100 entries
  BATCH_CREATE_1000: 60000, // 60 seconds for 1000 entries
  LIST_100_ENTRIES: 1000, // 1 second to list 100 entries
  LIST_1000_ENTRIES: 3000, // 3 seconds to list 1000 entries
  ENCRYPTION_SINGLE: 100, // 100ms for single entry encryption
  DECRYPTION_SINGLE: 100, // 100ms for single entry decryption
  PRIVACY_CHECK_SINGLE: 50, // 50ms for single privacy check
  HIPAA_VALIDATION: 200, // 200ms for HIPAA validation
  SEARCH_FILTER: 2000, // 2 seconds for filtered search
  CONCURRENT_READS: 5000, // 5 seconds for 50 concurrent reads
}

// Memory usage monitoring
interface MemoryUsage {
  initial: NodeJS.MemoryUsage
  peak: NodeJS.MemoryUsage
  final: NodeJS.MemoryUsage
  delta: {
    rss: number
    heapUsed: number
    heapTotal: number
    external: number
  }
}

class PerformanceMonitor {
  private startTime: number = 0
  private endTime: number = 0
  private memoryUsage: MemoryUsage

  constructor() {
    this.memoryUsage = {
      initial: process.memoryUsage(),
      peak: process.memoryUsage(),
      final: process.memoryUsage(),
      delta: { rss: 0, heapUsed: 0, heapTotal: 0, external: 0 },
    }
  }

  start(): void {
    this.startTime = Date.now()
    this.memoryUsage.initial = process.memoryUsage()
  }

  checkpoint(): void {
    const current = process.memoryUsage()
    if (current.heapUsed > this.memoryUsage.peak.heapUsed) {
      this.memoryUsage.peak = current
    }
  }

  end(): { duration: number; memory: MemoryUsage } {
    this.endTime = Date.now()
    this.memoryUsage.final = process.memoryUsage()
    
    this.memoryUsage.delta = {
      rss: this.memoryUsage.final.rss - this.memoryUsage.initial.rss,
      heapUsed: this.memoryUsage.final.heapUsed - this.memoryUsage.initial.heapUsed,
      heapTotal: this.memoryUsage.final.heapTotal - this.memoryUsage.initial.heapTotal,
      external: this.memoryUsage.final.external - this.memoryUsage.initial.external,
    }

    return {
      duration: this.endTime - this.startTime,
      memory: this.memoryUsage,
    }
  }

  getDuration(): number {
    return this.endTime - this.startTime
  }
}

describe('Journal System Performance Tests', () => {
  let network: TestNetworkNoAppView
  let ctx: AppContext
  let agent: AtpAgent
  let aliceAgent: AtpAgent
  let bobAgent: AtpAgent
  let charlieAgent: AtpAgent
  
  let accessManager: PrivacyAccessControlManager
  let hipaaManager: HIPAAComplianceManager
  let encryptionManager: EncryptionManager
  
  let aliceSecurityContext: SecurityContext
  let bobSecurityContext: SecurityContext
  let charlieSecurityContext: SecurityContext

  beforeAll(async () => {
    network = await TestNetworkNoAppView.create({
      dbPostgresSchema: 'journal_performance',
    })
    // @ts-expect-error Error due to circular dependency with the dev-env package
    ctx = network.pds.ctx
    agent = network.pds.getClient()
    aliceAgent = network.pds.getClient()
    bobAgent = network.pds.getClient()
    charlieAgent = network.pds.getClient()

    // Create test accounts
    await aliceAgent.createAccount({
      email: 'alice@perf.test',
      handle: 'alice.perf',
      password: 'alice-perf-pass',
    })

    await bobAgent.createAccount({
      email: 'bob@perf.test',
      handle: 'bob.perf',
      password: 'bob-perf-pass',
    })

    await charlieAgent.createAccount({
      email: 'charlie@perf.test',
      handle: 'charlie.perf',
      password: 'charlie-perf-pass',
    })

    // Initialize security managers
    accessManager = new PrivacyAccessControlManager()
    hipaaManager = HIPAAComplianceManager.getInstance()
    encryptionManager = new EncryptionManager()

    // Setup security contexts
    aliceSecurityContext = {
      userDid: aliceAgent.accountDid!,
      sessionId: 'alice-perf-session',
      ipAddress: '192.168.1.100',
      userAgent: 'Performance Test',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access', 'legal:evidence:access'],
    }

    bobSecurityContext = {
      userDid: bobAgent.accountDid!,
      sessionId: 'bob-perf-session',
      ipAddress: '192.168.1.101',
      userAgent: 'Performance Test',
      authLevel: 'basic',
      permissions: ['basic:read'],
    }

    charlieSecurityContext = {
      userDid: charlieAgent.accountDid!,
      sessionId: 'charlie-perf-session',
      ipAddress: '192.168.1.102',
      userAgent: 'Performance Test',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access'],
    }
  }, 30000) // Extended timeout for setup

  afterAll(async () => {
    await network.close()
  })

  describe('Single Entry Operations Performance', () => {
    it('measures single entry creation performance', async () => {
      const monitor = new PerformanceMonitor()
      const entryData = {
        $type: 'app.warlog.journal',
        text: 'Performance test entry for creation timing',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Performance test entry for creation timing',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      monitor.start()
      
      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: entryData,
      })
      
      const result = monitor.end()
      
      expect(res.data.uri).toBeDefined()
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.SINGLE_ENTRY_CREATE)
      expect(result.memory.delta.heapUsed).toBeLessThan(50 * 1024 * 1024) // Less than 50MB
      
      console.log(`Single entry creation: ${result.duration}ms, Memory delta: ${Math.round(result.memory.delta.heapUsed / 1024 / 1024)}MB`)

      // Cleanup
      const rkey = new AtUri(res.data.uri).rkey
      await aliceAgent.api.com.atproto.repo.deleteRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
    })

    it('measures single entry read performance', async () => {
      // Create test entry first
      const createRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Performance test entry for read timing',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Performance test entry for read timing',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(createRes.data.uri).rkey
      const monitor = new PerformanceMonitor()

      monitor.start()
      
      const res = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      
      const result = monitor.end()
      
      expect(res.data.value).toBeDefined()
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.SINGLE_ENTRY_READ)
      
      console.log(`Single entry read: ${result.duration}ms`)

      // Cleanup
      await aliceAgent.api.com.atproto.repo.deleteRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
    })

    it('measures single entry update performance', async () => {
      // Create test entry first
      const createRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Original text for update performance test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Original text for update performance test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(createRes.data.uri).rkey
      
      // Get current record
      const currentRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })

      const updatedRecord = {
        ...(currentRes.data.value as any),
        text: 'Updated text for performance measurement',
        content: {
          ...(currentRes.data.value as any).content,
          text: 'Updated text for performance measurement',
        },
      }

      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const res = await aliceAgent.api.com.atproto.repo.putRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
        record: updatedRecord,
      })
      
      const result = monitor.end()
      
      expect(res.data.cid).not.toBe(createRes.data.cid)
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.SINGLE_ENTRY_UPDATE)
      
      console.log(`Single entry update: ${result.duration}ms`)

      // Cleanup
      await aliceAgent.api.com.atproto.repo.deleteRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
    })

    it('measures single entry deletion performance', async () => {
      // Create test entry first
      const createRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Entry for deletion performance test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Entry for deletion performance test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(createRes.data.uri).rkey
      const monitor = new PerformanceMonitor()

      monitor.start()
      
      await aliceAgent.api.com.atproto.repo.deleteRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      
      const result = monitor.end()
      
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.SINGLE_ENTRY_DELETE)
      
      console.log(`Single entry deletion: ${result.duration}ms`)

      // Verify deletion
      await expect(
        aliceAgent.api.com.atproto.repo.getRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      ).rejects.toThrow()
    })
  })

  describe('Batch Operations Performance', () => {
    it('measures batch creation of 100 entries', async () => {
      const entryCount = 100
      const monitor = new PerformanceMonitor()
      const createdUris: string[] = []

      monitor.start()
      
      const createPromises = []
      for (let i = 0; i < entryCount; i++) {
        const entryData = {
          $type: 'app.warlog.journal',
          text: `Batch performance test entry ${i}`,
          entryType: 'real_time',
          privacyLevel: i % 3 === 0 ? PrivacyLevel.PUBLIC : PrivacyLevel.PRIVATE,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: `Batch performance test entry ${i}`,
            isEncrypted: i % 3 !== 0,
            encryptionLevel: i % 3 === 0 ? EncryptionLevel.NONE : EncryptionLevel.STANDARD,
          },
          tags: [`batch`, `test-${i}`, `group-${Math.floor(i / 10)}`],
          createdAt: new Date(Date.now() + i * 1000).toISOString(),
        }

        createPromises.push(
          aliceAgent.api.com.atproto.repo.createRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            record: entryData,
          })
        )
      }

      const results = await Promise.all(createPromises)
      
      const performanceResult = monitor.end()
      
      expect(results).toHaveLength(entryCount)
      expect(performanceResult.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BATCH_CREATE_100)
      expect(performanceResult.memory.delta.heapUsed).toBeLessThan(200 * 1024 * 1024) // Less than 200MB
      
      console.log(`Batch creation (${entryCount} entries): ${performanceResult.duration}ms, Memory delta: ${Math.round(performanceResult.memory.delta.heapUsed / 1024 / 1024)}MB`)

      results.forEach(result => {
        expect(result.data.uri).toBeDefined()
        createdUris.push(result.data.uri)
      })

      // Cleanup
      const deletePromises = createdUris.map(uri => {
        const rkey = new AtUri(uri).rkey
        return aliceAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      })

      await Promise.all(deletePromises)
    }, 30000) // Extended timeout for batch operations

    it('measures listing performance with 100 entries', async () => {
      const entryCount = 100
      const createdUris: string[] = []

      // Create entries first
      const createPromises = []
      for (let i = 0; i < entryCount; i++) {
        const entryData = {
          $type: 'app.warlog.journal',
          text: `List performance test entry ${i}`,
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: `List performance test entry ${i}`,
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date(Date.now() + i * 1000).toISOString(),
        }

        createPromises.push(
          aliceAgent.api.com.atproto.repo.createRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            record: entryData,
          })
        )
      }

      const createResults = await Promise.all(createPromises)
      createResults.forEach(result => createdUris.push(result.data.uri))

      // Measure listing performance
      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const listRes = await aliceAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        limit: 150, // More than we created to get all
      })
      
      const result = monitor.end()
      
      expect(listRes.data.records.length).toBeGreaterThanOrEqual(entryCount)
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.LIST_100_ENTRIES)
      
      console.log(`List ${entryCount} entries: ${result.duration}ms`)

      // Cleanup
      const deletePromises = createdUris.map(uri => {
        const rkey = new AtUri(uri).rkey
        return aliceAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      })

      await Promise.all(deletePromises)
    }, 30000)

    it('measures batch creation of 1000 entries', async () => {
      const entryCount = 1000
      const batchSize = 50 // Process in smaller batches to avoid overwhelming the system
      const monitor = new PerformanceMonitor()
      const createdUris: string[] = []

      monitor.start()
      
      for (let batchStart = 0; batchStart < entryCount; batchStart += batchSize) {
        const batchEnd = Math.min(batchStart + batchSize, entryCount)
        const batchPromises = []
        
        for (let i = batchStart; i < batchEnd; i++) {
          const entryData = {
            $type: 'app.warlog.journal',
            text: `Large batch performance test entry ${i}`,
            entryType: 'real_time',
            privacyLevel: i % 4 === 0 ? PrivacyLevel.PUBLIC : PrivacyLevel.PRIVATE,
            classification: SecurityClassification.UNCLASSIFIED,
            content: {
              text: `Large batch performance test entry ${i}`,
              isEncrypted: i % 4 !== 0,
              encryptionLevel: i % 4 === 0 ? EncryptionLevel.NONE : EncryptionLevel.STANDARD,
            },
            tags: [`large-batch`, `test-${i}`, `batch-${Math.floor(i / 100)}`],
            createdAt: new Date(Date.now() + i * 100).toISOString(), // Smaller time intervals
          }

          batchPromises.push(
            aliceAgent.api.com.atproto.repo.createRecord({
              repo: aliceAgent.accountDid!,
              collection: 'app.warlog.journal',
              record: entryData,
            })
          )
        }

        const batchResults = await Promise.all(batchPromises)
        batchResults.forEach(result => createdUris.push(result.data.uri))
        
        monitor.checkpoint() // Monitor peak memory usage
      }
      
      const performanceResult = monitor.end()
      
      expect(createdUris).toHaveLength(entryCount)
      expect(performanceResult.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.BATCH_CREATE_1000)
      expect(performanceResult.memory.delta.heapUsed).toBeLessThan(500 * 1024 * 1024) // Less than 500MB
      
      console.log(`Large batch creation (${entryCount} entries): ${performanceResult.duration}ms, Memory delta: ${Math.round(performanceResult.memory.delta.heapUsed / 1024 / 1024)}MB, Peak: ${Math.round(performanceResult.memory.peak.heapUsed / 1024 / 1024)}MB`)

      // Test listing large dataset
      const listMonitor = new PerformanceMonitor()
      listMonitor.start()
      
      const listRes = await aliceAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        limit: 1100, // More than we created
      })
      
      const listResult = listMonitor.end()
      
      expect(listRes.data.records.length).toBeGreaterThanOrEqual(entryCount)
      expect(listResult.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.LIST_1000_ENTRIES)
      
      console.log(`List ${entryCount} entries: ${listResult.duration}ms`)

      // Cleanup in batches
      for (let batchStart = 0; batchStart < createdUris.length; batchStart += batchSize) {
        const batchEnd = Math.min(batchStart + batchSize, createdUris.length)
        const deleteBatch = createdUris.slice(batchStart, batchEnd)
        
        const deletePromises = deleteBatch.map(uri => {
          const rkey = new AtUri(uri).rkey
          return aliceAgent.api.com.atproto.repo.deleteRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            rkey: rkey,
          })
        })

        await Promise.all(deletePromises)
      }
    }, 120000) // Extended timeout for large batch operations
  })

  describe('Encryption Performance', () => {
    it('measures single entry encryption performance', async () => {
      const plaintext = 'Test data for encryption performance measurement'
      const keyId = 'perf-test-key-123'
      const monitor = new PerformanceMonitor()

      monitor.start()
      
      const encrypted = await encryptionManager.encrypt(
        plaintext,
        keyId,
        EncryptionLevel.STANDARD
      )
      
      const result = monitor.end()
      
      expect(encrypted.data).toBeDefined()
      expect(encrypted.metadata).toBeDefined()
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.ENCRYPTION_SINGLE)
      
      console.log(`Single encryption: ${result.duration}ms`)
    })

    it('measures single entry decryption performance', async () => {
      const plaintext = 'Test data for decryption performance measurement'
      const keyId = 'perf-test-key-456'
      
      // Encrypt first
      const encrypted = await encryptionManager.encrypt(
        plaintext,
        keyId,
        EncryptionLevel.STANDARD
      )

      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const decrypted = await encryptionManager.decrypt(
        encrypted.data,
        encrypted.metadata
      )
      
      const result = monitor.end()
      
      expect(decrypted).toBe(plaintext)
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.DECRYPTION_SINGLE)
      
      console.log(`Single decryption: ${result.duration}ms`)
    })

    it('measures enhanced encryption performance', async () => {
      const plaintext = 'Sensitive data for enhanced encryption performance test'
      const keyId = 'perf-test-enhanced-key'
      const monitor = new PerformanceMonitor()

      monitor.start()
      
      const encrypted = await encryptionManager.encrypt(
        plaintext,
        keyId,
        EncryptionLevel.ENHANCED
      )
      
      const result = monitor.end()
      
      expect(encrypted.data).toBeDefined()
      expect(encrypted.metadata.algorithm).toContain('AES-256')
      // Enhanced encryption may take longer but should still be reasonable
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.ENCRYPTION_SINGLE * 3)
      
      console.log(`Enhanced encryption: ${result.duration}ms`)

      // Test decryption performance
      const decryptMonitor = new PerformanceMonitor()
      decryptMonitor.start()
      
      const decrypted = await encryptionManager.decrypt(
        encrypted.data,
        encrypted.metadata
      )
      
      const decryptResult = decryptMonitor.end()
      
      expect(decrypted).toBe(plaintext)
      expect(decryptResult.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.DECRYPTION_SINGLE * 3)
      
      console.log(`Enhanced decryption: ${decryptResult.duration}ms`)
    })

    it('measures batch encryption performance', async () => {
      const dataItems = Array.from({ length: 100 }, (_, i) => 
        `Performance test data item ${i} with some additional content to make it realistic`
      )
      const keyId = 'perf-test-batch-key'
      const monitor = new PerformanceMonitor()

      monitor.start()
      
      const encryptPromises = dataItems.map(data =>
        encryptionManager.encrypt(data, keyId, EncryptionLevel.STANDARD)
      )
      
      const encrypted = await Promise.all(encryptPromises)
      
      const result = monitor.end()
      
      expect(encrypted).toHaveLength(100)
      encrypted.forEach(item => {
        expect(item.data).toBeDefined()
        expect(item.metadata).toBeDefined()
      })
      
      // Batch encryption should be efficient
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.ENCRYPTION_SINGLE * 100)
      
      console.log(`Batch encryption (100 items): ${result.duration}ms, avg: ${Math.round(result.duration / 100)}ms per item`)

      // Test batch decryption
      const decryptMonitor = new PerformanceMonitor()
      decryptMonitor.start()
      
      const decryptPromises = encrypted.map(item =>
        encryptionManager.decrypt(item.data, item.metadata)
      )
      
      const decrypted = await Promise.all(decryptPromises)
      
      const decryptResult = decryptMonitor.end()
      
      expect(decrypted).toHaveLength(100)
      expect(decrypted).toEqual(dataItems)
      
      console.log(`Batch decryption (100 items): ${decryptResult.duration}ms, avg: ${Math.round(decryptResult.duration / 100)}ms per item`)
    })
  })

  describe('Privacy and Security Performance', () => {
    it('measures privacy access control check performance', async () => {
      const testEntry = {
        uri: 'at://did:example:test/app.warlog.journal/perf123',
        cid: 'bafkreiperftest123',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.perf',
          displayName: 'Alice Performance',
        },
        text: 'Privacy check performance test entry',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Privacy check performance test entry',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
        },
        accessControlList: [bobAgent.accountDid!, charlieAgent.accountDid!],
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const accessResult = await accessManager.checkAccess(testEntry, bobSecurityContext)
      
      const result = monitor.end()
      
      expect(accessResult.hasAccess).toBe(true)
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.PRIVACY_CHECK_SINGLE)
      
      console.log(`Privacy access check: ${result.duration}ms`)
    })

    it('measures HIPAA compliance validation performance', async () => {
      const phiEntry = {
        uri: 'at://did:example:test/app.warlog.journal/phi123',
        cid: 'bafkreiphitest123',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.perf',
          displayName: 'Alice Performance',
        },
        text: 'HIPAA validation performance test',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'HIPAA validation performance test',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'hipaa-perf-key',
            iv: 'hipaa-perf-iv',
            salt: 'hipaa-perf-salt',
            signature: 'hipaa-perf-signature',
          },
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptoms-perf-test',
          count: 3,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const complianceResult = hipaaManager.validateHIPAACompliance(phiEntry)
      
      const result = monitor.end()
      
      expect(complianceResult.isCompliant).toBe(true)
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.HIPAA_VALIDATION)
      
      console.log(`HIPAA compliance validation: ${result.duration}ms`)
    })

    it('measures concurrent privacy checks performance', async () => {
      const testEntries = Array.from({ length: 50 }, (_, i) => ({
        uri: `at://did:example:test/app.warlog.journal/concurrent${i}`,
        cid: `bafkreiconcurrent${i}`,
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.perf',
        },
        text: `Concurrent privacy test entry ${i}`,
        entryType: 'real_time' as const,
        privacyLevel: i % 3 === 0 ? PrivacyLevel.PUBLIC : PrivacyLevel.PRIVATE,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: `Concurrent privacy test entry ${i}`,
          isEncrypted: i % 3 !== 0,
          encryptionLevel: i % 3 === 0 ? EncryptionLevel.NONE : EncryptionLevel.STANDARD,
        },
        accessControlList: i % 3 !== 0 ? [bobAgent.accountDid!] : undefined,
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }))

      const monitor = new PerformanceMonitor()
      monitor.start()
      
      const accessPromises = testEntries.map(entry =>
        accessManager.checkAccess(entry, bobSecurityContext)
      )
      
      const accessResults = await Promise.all(accessPromises)
      
      const result = monitor.end()
      
      expect(accessResults).toHaveLength(50)
      accessResults.forEach((accessResult, i) => {
        const isPublic = testEntries[i].privacyLevel === PrivacyLevel.PUBLIC
        const hasExplicitAccess = testEntries[i].accessControlList?.includes(bobAgent.accountDid!)
        expect(accessResult.hasAccess).toBe(isPublic || hasExplicitAccess)
      })
      
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.CONCURRENT_READS)
      
      console.log(`Concurrent privacy checks (50 entries): ${result.duration}ms, avg: ${Math.round(result.duration / 50)}ms per check`)
    })
  })

  describe('Search and Filtering Performance', () => {
    it('measures filtered search performance', async () => {
      const entryCount = 200
      const createdUris: string[] = []
      
      // Create diverse dataset for searching
      const createPromises = []
      for (let i = 0; i < entryCount; i++) {
        const entryData = {
          $type: 'app.warlog.journal',
          text: `Search performance test entry ${i} with harassment and surveillance content`,
          entryType: i % 5 === 0 ? 'backdated' : 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: `Search performance test entry ${i} with harassment and surveillance content`,
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          tags: [
            'search-test',
            i % 3 === 0 ? 'harassment' : 'other',
            i % 5 === 0 ? 'surveillance' : 'regular',
            `category-${i % 10}`,
          ],
          location: i % 7 === 0 ? {
            encrypted: false,
            data: JSON.stringify({ latitude: 40.7128, longitude: -74.0060 }),
            accuracy: 10,
          } : undefined,
          symptoms: i % 11 === 0 ? {
            encrypted: false,
            data: 'test-symptoms',
            count: 2,
          } : undefined,
          createdAt: new Date(Date.now() + i * 60000).toISOString(), // 1 minute intervals
        }

        createPromises.push(
          aliceAgent.api.com.atproto.repo.createRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            record: entryData,
          })
        )
      }

      const createResults = await Promise.all(createPromises)
      createResults.forEach(result => createdUris.push(result.data.uri))

      // Test various search scenarios
      const monitor = new PerformanceMonitor()
      monitor.start()
      
      // Simulate filtering by listing and client-side filtering
      const listRes = await aliceAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        limit: 250, // Get all entries
      })
      
      // Client-side filtering simulation
      const allEntries = listRes.data.records.filter(r => 
        createdUris.includes(r.uri)
      )
      
      // Filter by tags (harassment)
      const harassmentEntries = allEntries.filter(r => {
        const entry = r.value as any
        return entry.tags?.includes('harassment')
      })
      
      // Filter by entry type (backdated)
      const backdatedEntries = allEntries.filter(r => {
        const entry = r.value as any
        return entry.entryType === 'backdated'
      })
      
      // Filter by presence of location
      const locationEntries = allEntries.filter(r => {
        const entry = r.value as any
        return entry.location !== undefined
      })
      
      // Filter by presence of symptoms
      const symptomEntries = allEntries.filter(r => {
        const entry = r.value as any
        return entry.symptoms !== undefined
      })
      
      // Text search simulation
      const searchTermEntries = allEntries.filter(r => {
        const entry = r.value as any
        return entry.text.toLowerCase().includes('surveillance')
      })
      
      const result = monitor.end()
      
      // Verify filtering results
      expect(allEntries).toHaveLength(entryCount)
      expect(harassmentEntries.length).toBeGreaterThan(0)
      expect(backdatedEntries.length).toBeGreaterThan(0)
      expect(locationEntries.length).toBeGreaterThan(0)
      expect(symptomEntries.length).toBeGreaterThan(0)
      expect(searchTermEntries.length).toBeGreaterThan(0)
      
      expect(result.duration).toBeLessThan(PERFORMANCE_THRESHOLDS.SEARCH_FILTER)
      
      console.log(`Filtered search (${entryCount} entries): ${result.duration}ms`)
      console.log(`  - Harassment entries: ${harassmentEntries.length}`)
      console.log(`  - Backdated entries: ${backdatedEntries.length}`)
      console.log(`  - Location entries: ${locationEntries.length}`)
      console.log(`  - Symptom entries: ${symptomEntries.length}`)
      console.log(`  - Search term matches: ${searchTermEntries.length}`)

      // Cleanup
      const deletePromises = createdUris.map(uri => {
        const rkey = new AtUri(uri).rkey
        return aliceAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      })

      await Promise.all(deletePromises)
    }, 60000) // Extended timeout for search operations
  })

  describe('Memory Usage and Resource Management', () => {
    it('monitors memory usage during large operations', async () => {
      const monitor = new PerformanceMonitor()
      const entryCount = 500
      const createdUris: string[] = []

      console.log(`Initial memory usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`)
      
      monitor.start()
      
      // Create entries and monitor memory growth
      for (let i = 0; i < entryCount; i++) {
        const entryData = {
          $type: 'app.warlog.journal',
          text: `Memory test entry ${i} `.repeat(10), // Make entries larger
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: `Memory test entry ${i} `.repeat(10),
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          tags: Array.from({ length: 10 }, (_, j) => `tag-${i}-${j}`),
          createdAt: new Date(Date.now() + i * 1000).toISOString(),
        }

        const res = await aliceAgent.api.com.atproto.repo.createRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          record: entryData,
        })
        
        createdUris.push(res.data.uri)
        
        // Monitor memory every 50 entries
        if (i % 50 === 0) {
          monitor.checkpoint()
          const currentMemory = process.memoryUsage()
          console.log(`  Entry ${i}: ${Math.round(currentMemory.heapUsed / 1024 / 1024)}MB`)
        }
      }
      
      const result = monitor.end()
      
      console.log(`Memory usage after ${entryCount} entries:`)
      console.log(`  Initial: ${Math.round(result.memory.initial.heapUsed / 1024 / 1024)}MB`)
      console.log(`  Peak: ${Math.round(result.memory.peak.heapUsed / 1024 / 1024)}MB`)
      console.log(`  Final: ${Math.round(result.memory.final.heapUsed / 1024 / 1024)}MB`)
      console.log(`  Delta: ${Math.round(result.memory.delta.heapUsed / 1024 / 1024)}MB`)
      
      // Memory growth should be reasonable
      expect(result.memory.delta.heapUsed).toBeLessThan(1000 * 1024 * 1024) // Less than 1GB growth
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc()
        const afterGC = process.memoryUsage()
        console.log(`  After GC: ${Math.round(afterGC.heapUsed / 1024 / 1024)}MB`)
      }

      // Cleanup
      const batchSize = 50
      for (let i = 0; i < createdUris.length; i += batchSize) {
        const batch = createdUris.slice(i, i + batchSize)
        const deletePromises = batch.map(uri => {
          const rkey = new AtUri(uri).rkey
          return aliceAgent.api.com.atproto.repo.deleteRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            rkey: rkey,
          })
        })
        await Promise.all(deletePromises)
      }
      
      console.log(`Final memory after cleanup: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`)
    }, 120000) // Extended timeout for memory testing

    it('validates no memory leaks in repeated operations', async () => {
      const initialMemory = process.memoryUsage()
      const iterationCount = 100
      
      console.log(`Starting memory leak test with ${iterationCount} iterations`)
      console.log(`Initial memory: ${Math.round(initialMemory.heapUsed / 1024 / 1024)}MB`)
      
      for (let iteration = 0; iteration < iterationCount; iteration++) {
        // Create, read, update, delete cycle
        const entryData = {
          $type: 'app.warlog.journal',
          text: `Memory leak test iteration ${iteration}`,
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: `Memory leak test iteration ${iteration}`,
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        }

        // Create
        const createRes = await aliceAgent.api.com.atproto.repo.createRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          record: entryData,
        })
        
        const rkey = new AtUri(createRes.data.uri).rkey
        
        // Read
        const readRes = await aliceAgent.api.com.atproto.repo.getRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
        
        // Update
        const updatedEntry = {
          ...(readRes.data.value as any),
          text: `Updated memory leak test iteration ${iteration}`,
        }
        
        await aliceAgent.api.com.atproto.repo.putRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
          record: updatedEntry,
        })
        
        // Delete
        await aliceAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
        
        // Check memory every 25 iterations
        if (iteration % 25 === 0 && iteration > 0) {
          const currentMemory = process.memoryUsage()
          console.log(`  Iteration ${iteration}: ${Math.round(currentMemory.heapUsed / 1024 / 1024)}MB`)
        }
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc()
      }
      
      const finalMemory = process.memoryUsage()
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed
      
      console.log(`Final memory: ${Math.round(finalMemory.heapUsed / 1024 / 1024)}MB`)
      console.log(`Memory growth: ${Math.round(memoryGrowth / 1024 / 1024)}MB`)
      
      // Memory growth should be minimal for repeated operations
      expect(memoryGrowth).toBeLessThan(100 * 1024 * 1024) // Less than 100MB growth
    }, 60000)
  })
})
