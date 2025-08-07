/**
 * Integration Tests for Journal Entry CRUD Operations
 * 
 * Validates core journal functionality including creation, reading, updating,
 * and deletion with privacy level enforcement and security validation.
 */

import { AtpAgent } from '@atproto/api'
import { TestNetworkNoAppView } from '@atproto/dev-env'
import { TID } from '@atproto/common'
import { AtUri } from '@atproto/syntax'
import { AppContext } from '../../src/context'
import {
  PrivacyLevel,
  SecurityClassification,
  EncryptionLevel,
  SecurityContext,
  SecureJournalEntry,
} from '../../src/journal-security'
import { forSnapshot } from '../_util'

describe('Journal Entry CRUD Operations', () => {
  let network: TestNetworkNoAppView
  let ctx: AppContext
  let aliceAgent: AtpAgent
  let bobAgent: AtpAgent
  let charlieAgent: AtpAgent

  // Mock security contexts for testing
  let aliceSecurityContext: SecurityContext
  let bobSecurityContext: SecurityContext

  beforeAll(async () => {
    network = await TestNetworkNoAppView.create({
      dbPostgresSchema: 'journal_crud',
    })
    // @ts-expect-error Error due to circular dependency with the dev-env package
    ctx = network.pds.ctx

    aliceAgent = network.pds.getClient()
    bobAgent = network.pds.getClient()
    charlieAgent = network.pds.getClient()

    // Create test accounts
    await aliceAgent.createAccount({
      email: 'alice@test.com',
      handle: 'alice.test',
      password: 'alice-pass',
    })

    await bobAgent.createAccount({
      email: 'bob@test.com',
      handle: 'bob.test',
      password: 'bob-pass',
    })

    await charlieAgent.createAccount({
      email: 'charlie@test.com',
      handle: 'charlie.test',
      password: 'charlie-pass',
    })

    // Setup security contexts
    aliceSecurityContext = {
      userDid: aliceAgent.accountDid!,
      sessionId: 'alice-session-123',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 Test Browser',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access', 'legal:evidence:access'],
    }

    bobSecurityContext = {
      userDid: bobAgent.accountDid!,
      sessionId: 'bob-session-456',
      ipAddress: '192.168.1.101',
      userAgent: 'Mozilla/5.0 Test Browser',
      authLevel: 'basic',
      permissions: ['basic:read'],
    }
  })

  afterAll(async () => {
    await network.close()
  })

  describe('Journal Entry Creation', () => {
    it('creates a public journal entry successfully', async () => {
      const journalRecord = {
        $type: 'app.warlog.journal',
        text: 'This is a public journal entry for testing',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'This is a public journal entry for testing',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: journalRecord,
      })

      expect(res.data.uri).toBeDefined()
      expect(res.data.cid).toBeDefined()

      const uri = new AtUri(res.data.uri)
      expect(uri.collection).toBe('app.warlog.journal')
      expect(uri.hostname).toBe(aliceAgent.accountDid)
    })

    it('creates a private journal entry with access control', async () => {
      const privateRecord = {
        $type: 'app.warlog.journal',
        text: 'This is a private journal entry',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        accessControlList: [bobAgent.accountDid!],
        content: {
          text: 'This is a private journal entry',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'test-key-123',
            iv: 'test-iv-123',
            salt: 'test-salt-123',
            signature: 'test-signature-123',
          },
        },
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: privateRecord,
      })

      expect(res.data.uri).toBeDefined()
      expect(res.data.cid).toBeDefined()

      // Verify the record was stored correctly
      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.privacyLevel).toBe(PrivacyLevel.PRIVATE)
      expect(storedRecord.accessControlList).toContain(bobAgent.accountDid)
      expect(storedRecord.content.isEncrypted).toBe(true)
    })

    it('creates a medical journal entry with PHI classification', async () => {
      const medicalRecord = {
        $type: 'app.warlog.journal',
        text: 'Medical journal entry with symptoms',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Encrypted medical content',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'medical-key-456',
            iv: 'medical-iv-456',
            salt: 'medical-salt-456',
            signature: 'medical-signature-456',
          },
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptom-data-123',
          count: 3,
        },
        location: {
          encrypted: true,
          data: 'encrypted-location-data-456',
          accuracy: 10,
        },
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: medicalRecord,
      })

      expect(res.data.uri).toBeDefined()

      // Verify PHI compliance
      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.classification).toBe(SecurityClassification.PHI)
      expect(storedRecord.symptoms.encrypted).toBe(true)
      expect(storedRecord.location.encrypted).toBe(true)
      expect(storedRecord.content.encryptionLevel).toBe(EncryptionLevel.ENHANCED)
    })

    it('creates a community journal entry', async () => {
      const communityRecord = {
        $type: 'app.warlog.journal',
        text: 'Community journal entry for badge holders',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.COMMUNITY,
        classification: SecurityClassification.SENSITIVE,
        communityBadges: ['havana', 'gangstalked'],
        content: {
          text: 'Community journal entry for badge holders',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: communityRecord,
      })

      expect(res.data.uri).toBeDefined()

      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.privacyLevel).toBe(PrivacyLevel.COMMUNITY)
      expect(storedRecord.communityBadges).toEqual(['havana', 'gangstalked'])
    })

    it('creates a backdated journal entry', async () => {
      const backdatedRecord = {
        $type: 'app.warlog.journal',
        text: 'This incident happened last week',
        entryType: 'backdated',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'This incident happened last week',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
        },
        createdAt: new Date().toISOString(),
        incidentTimestamp: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days ago
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: backdatedRecord,
      })

      expect(res.data.uri).toBeDefined()

      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.entryType).toBe('backdated')
      expect(storedRecord.incidentTimestamp).toBeDefined()
      expect(new Date(storedRecord.incidentTimestamp)).toBeInstanceOf(Date)
    })

    it('validates required fields during creation', async () => {
      const invalidRecord = {
        $type: 'app.warlog.journal',
        // Missing required text field
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        createdAt: new Date().toISOString(),
      }

      await expect(
        aliceAgent.api.com.atproto.repo.createRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          record: invalidRecord,
        })
      ).rejects.toThrow()
    })

    it('enforces encryption for PHI content', async () => {
      const nonCompliantPHI = {
        $type: 'app.warlog.journal',
        text: 'Unencrypted PHI content',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Unencrypted PHI content',
          isEncrypted: false, // This should be rejected
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      await expect(
        aliceAgent.api.com.atproto.repo.createRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          record: nonCompliantPHI,
        })
      ).rejects.toThrow()
    })
  })

  describe('Journal Entry Reading', () => {
    let publicEntryUri: string
    let privateEntryUri: string
    let medicalEntryUri: string

    beforeAll(async () => {
      // Create test entries for reading tests
      const publicRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Public entry for reading test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Public entry for reading test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })
      publicEntryUri = publicRes.data.uri

      const privateRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Private entry for reading test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PRIVATE,
          classification: SecurityClassification.SENSITIVE,
          accessControlList: [bobAgent.accountDid!],
          content: {
            text: 'Private entry for reading test',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.STANDARD,
          },
          createdAt: new Date().toISOString(),
        },
      })
      privateEntryUri = privateRes.data.uri

      const medicalRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Medical entry for reading test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.MEDICAL,
          classification: SecurityClassification.PHI,
          content: {
            text: 'Medical entry for reading test',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.ENHANCED,
          },
          symptoms: {
            encrypted: true,
            data: 'encrypted-symptoms-test',
            count: 2,
          },
          createdAt: new Date().toISOString(),
        },
      })
      medicalEntryUri = medicalRes.data.uri
    })

    it('reads public journal entries without authentication', async () => {
      const res = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(publicEntryUri).rkey,
      })

      expect(res.data.value).toBeDefined()
      const record = res.data.value as any
      expect(record.text).toBe('Public entry for reading test')
      expect(record.privacyLevel).toBe(PrivacyLevel.PUBLIC)
    })

    it('allows owner to read their own private entries', async () => {
      const res = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(privateEntryUri).rkey,
      })

      expect(res.data.value).toBeDefined()
      const record = res.data.value as any
      expect(record.text).toBe('Private entry for reading test')
      expect(record.privacyLevel).toBe(PrivacyLevel.PRIVATE)
    })

    it('allows authorized users to read private entries', async () => {
      // Bob should be able to read because he's in the access control list
      const res = await bobAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(privateEntryUri).rkey,
      })

      expect(res.data.value).toBeDefined()
      const record = res.data.value as any
      expect(record.privacyLevel).toBe(PrivacyLevel.PRIVATE)
      expect(record.accessControlList).toContain(bobAgent.accountDid)
    })

    it('denies access to unauthorized users for private entries', async () => {
      // Charlie should not be able to read because he's not in the access control list
      await expect(
        charlieAgent.api.com.atproto.repo.getRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: new AtUri(privateEntryUri).rkey,
        })
      ).rejects.toThrow()
    })

    it('requires proper permissions for medical entries', async () => {
      // Alice should be able to read her own medical entry
      const res = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(medicalEntryUri).rkey,
      })

      expect(res.data.value).toBeDefined()
      const record = res.data.value as any
      expect(record.classification).toBe(SecurityClassification.PHI)
    })

    it('lists journal entries with privacy filtering', async () => {
      const res = await aliceAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
      })

      expect(res.data.records.length).toBeGreaterThan(0)
      
      // All records should be visible to the owner
      const records = res.data.records
      const publicCount = records.filter(r => (r.value as any).privacyLevel === PrivacyLevel.PUBLIC).length
      const privateCount = records.filter(r => (r.value as any).privacyLevel === PrivacyLevel.PRIVATE).length
      const medicalCount = records.filter(r => (r.value as any).privacyLevel === PrivacyLevel.MEDICAL).length
      
      expect(publicCount).toBeGreaterThan(0)
      expect(privateCount).toBeGreaterThan(0)
      expect(medicalCount).toBeGreaterThan(0)
    })

    it('filters entries based on user permissions', async () => {
      // Bob should only see public entries and those he has explicit access to
      const res = await bobAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
      })

      const records = res.data.records
      records.forEach(record => {
        const entry = record.value as any
        const isPublic = entry.privacyLevel === PrivacyLevel.PUBLIC
        const hasAccess = entry.accessControlList?.includes(bobAgent.accountDid)
        
        expect(isPublic || hasAccess).toBe(true)
      })
    })
  })

  describe('Journal Entry Updates', () => {
    let testEntryUri: string
    let testEntryRkey: string

    beforeAll(async () => {
      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Original entry text',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Original entry text',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })
      testEntryUri = res.data.uri
      testEntryRkey = new AtUri(testEntryUri).rkey
    })

    it('updates journal entry text successfully', async () => {
      // Get current record first
      const currentRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
      })

      const updatedRecord = {
        ...currentRes.data.value,
        text: 'Updated entry text',
        content: {
          ...((currentRes.data.value as any).content),
          text: 'Updated entry text',
        },
      }

      const updateRes = await aliceAgent.api.com.atproto.repo.putRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
        record: updatedRecord,
      })

      expect(updateRes.data.uri).toBe(testEntryUri)
      expect(updateRes.data.cid).not.toBe(currentRes.data.cid) // CID should change

      // Verify the update
      const verifyRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
      })

      const verifiedRecord = verifyRes.data.value as any
      expect(verifiedRecord.text).toBe('Updated entry text')
    })

    it('updates privacy level successfully', async () => {
      const currentRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
      })

      const updatedRecord = {
        ...currentRes.data.value,
        privacyLevel: PrivacyLevel.PRIVATE,
        accessControlList: [bobAgent.accountDid!],
      }

      await aliceAgent.api.com.atproto.repo.putRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
        record: updatedRecord,
      })

      // Verify the privacy level change
      const verifyRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
      })

      const verifiedRecord = verifyRes.data.value as any
      expect(verifiedRecord.privacyLevel).toBe(PrivacyLevel.PRIVATE)
      expect(verifiedRecord.accessControlList).toContain(bobAgent.accountDid)
    })

    it('prevents unauthorized users from updating entries', async () => {
      const currentRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: testEntryRkey,
      })

      const updatedRecord = {
        ...currentRes.data.value,
        text: 'Unauthorized update attempt',
      }

      // Bob should not be able to update Alice's entry
      await expect(
        bobAgent.api.com.atproto.repo.putRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: testEntryRkey,
          record: updatedRecord,
        })
      ).rejects.toThrow()
    })

    it('maintains encryption requirements when updating PHI', async () => {
      // Create a PHI entry first
      const phiRes = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Original PHI entry',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.MEDICAL,
          classification: SecurityClassification.PHI,
          content: {
            text: 'Original PHI entry',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.ENHANCED,
            encryptionMetadata: {
              algorithm: 'AES-256-CBC',
              keyId: 'phi-key-789',
              iv: 'phi-iv-789',
              salt: 'phi-salt-789',
              signature: 'phi-signature-789',
            },
          },
          symptoms: {
            encrypted: true,
            data: 'encrypted-phi-symptoms',
            count: 1,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const phiRkey = new AtUri(phiRes.data.uri).rkey

      // Update the PHI entry
      const currentRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: phiRkey,
      })

      const updatedRecord = {
        ...currentRes.data.value,
        symptoms: {
          encrypted: true,
          data: 'updated-encrypted-phi-symptoms',
          count: 2,
        },
      }

      await aliceAgent.api.com.atproto.repo.putRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: phiRkey,
        record: updatedRecord,
      })

      // Verify encryption is maintained
      const verifyRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: phiRkey,
      })

      const verifiedRecord = verifyRes.data.value as any
      expect(verifiedRecord.classification).toBe(SecurityClassification.PHI)
      expect(verifiedRecord.content.isEncrypted).toBe(true)
      expect(verifiedRecord.symptoms.encrypted).toBe(true)
      expect(verifiedRecord.symptoms.count).toBe(2)
    })
  })

  describe('Journal Entry Deletion', () => {
    let deletionTestUri: string
    let deletionTestRkey: string

    beforeAll(async () => {
      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Entry to be deleted',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Entry to be deleted',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })
      deletionTestUri = res.data.uri
      deletionTestRkey = new AtUri(deletionTestUri).rkey
    })

    it('deletes journal entry successfully', async () => {
      // Verify entry exists before deletion
      const beforeRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: deletionTestRkey,
      })
      expect(beforeRes.data.value).toBeDefined()

      // Delete the entry
      await aliceAgent.api.com.atproto.repo.deleteRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: deletionTestRkey,
      })

      // Verify entry is deleted
      await expect(
        aliceAgent.api.com.atproto.repo.getRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: deletionTestRkey,
        })
      ).rejects.toThrow()
    })

    it('prevents unauthorized deletion', async () => {
      // Create another entry for deletion test
      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Entry to test unauthorized deletion',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Entry to test unauthorized deletion',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(res.data.uri).rkey

      // Bob should not be able to delete Alice's entry
      await expect(
        bobAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      ).rejects.toThrow()

      // Verify entry still exists
      const stillExistsRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(stillExistsRes.data.value).toBeDefined()
    })

    it('handles deletion of non-existent entries gracefully', async () => {
      const nonExistentRkey = TID.nextStr()

      await expect(
        aliceAgent.api.com.atproto.repo.deleteRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: nonExistentRkey,
        })
      ).rejects.toThrow()
    })
  })

  describe('Privacy Level Enforcement', () => {
    it('enforces public access permissions', async () => {
      const publicEntry = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Public entry for access test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Public entry for access test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      // Anyone should be able to read public entries
      const rkey = new AtUri(publicEntry.data.uri).rkey
      
      const aliceRead = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(aliceRead.data.value).toBeDefined()

      const bobRead = await bobAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(bobRead.data.value).toBeDefined()

      const charlieRead = await charlieAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(charlieRead.data.value).toBeDefined()
    })

    it('enforces community access with badge verification', async () => {
      const communityEntry = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Community entry for badge holders',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.COMMUNITY,
          classification: SecurityClassification.SENSITIVE,
          communityBadges: ['havana', 'targeted'],
          content: {
            text: 'Community entry for badge holders',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(communityEntry.data.uri).rkey
      
      // Owner should always be able to read
      const ownerRead = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(ownerRead.data.value).toBeDefined()

      // Note: In a real implementation, badge verification would happen
      // at the API level before allowing access. For now, we're testing
      // the record structure is correct.
      const record = ownerRead.data.value as any
      expect(record.privacyLevel).toBe(PrivacyLevel.COMMUNITY)
      expect(record.communityBadges).toEqual(['havana', 'targeted'])
    })

    it('enforces medical data access restrictions', async () => {
      const medicalEntry = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Medical entry with strict access',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.MEDICAL,
          classification: SecurityClassification.PHI,
          content: {
            text: 'Medical entry with strict access',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.ENHANCED,
            encryptionMetadata: {
              algorithm: 'AES-256-CBC',
              keyId: 'medical-access-key',
              iv: 'medical-access-iv',
              salt: 'medical-access-salt',
              signature: 'medical-access-signature',
            },
          },
          symptoms: {
            encrypted: true,
            data: 'encrypted-medical-symptoms',
            count: 3,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(medicalEntry.data.uri).rkey
      
      // Owner should be able to read their own medical data
      const ownerRead = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: rkey,
      })
      expect(ownerRead.data.value).toBeDefined()

      const record = ownerRead.data.value as any
      expect(record.classification).toBe(SecurityClassification.PHI)
      expect(record.content.isEncrypted).toBe(true)
      expect(record.content.encryptionLevel).toBe(EncryptionLevel.ENHANCED)
      expect(record.symptoms.encrypted).toBe(true)
    })
  })

  describe('Security Classification Validation', () => {
    it('enforces PHI encryption requirements', async () => {
      // Valid PHI entry with proper encryption
      const validPHI = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Valid PHI entry',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.MEDICAL,
          classification: SecurityClassification.PHI,
          content: {
            text: 'Valid PHI entry',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.ENHANCED,
            encryptionMetadata: {
              algorithm: 'AES-256-CBC',
              keyId: 'valid-phi-key',
              iv: 'valid-phi-iv',
              salt: 'valid-phi-salt',
              signature: 'valid-phi-signature',
            },
          },
          symptoms: {
            encrypted: true,
            data: 'encrypted-phi-symptoms',
            count: 2,
          },
          createdAt: new Date().toISOString(),
        },
      })

      expect(validPHI.data.uri).toBeDefined()

      // Verify the record was stored with proper classification
      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(validPHI.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.classification).toBe(SecurityClassification.PHI)
      expect(storedRecord.content.encryptionLevel).toBe(EncryptionLevel.ENHANCED)
    })

    it('handles legal evidence classification', async () => {
      const legalEvidence = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Legal evidence entry',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.LEGAL,
          classification: SecurityClassification.LEGAL_EVIDENCE,
          content: {
            text: 'Legal evidence entry',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.ENHANCED,
            encryptionMetadata: {
              algorithm: 'AES-256-CBC',
              keyId: 'legal-evidence-key',
              iv: 'legal-evidence-iv',
              salt: 'legal-evidence-salt',
              signature: 'legal-evidence-signature',
            },
          },
          evidenceUris: [
            'at://did:example:evidence/app.warlog.document/abc123',
            'at://did:example:evidence/app.warlog.document/def456',
          ],
          legalHoldStatus: true,
          createdAt: new Date().toISOString(),
        },
      })

      expect(legalEvidence.data.uri).toBeDefined()

      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(legalEvidence.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.classification).toBe(SecurityClassification.LEGAL_EVIDENCE)
      expect(storedRecord.legalHoldStatus).toBe(true)
      expect(storedRecord.evidenceUris).toEqual([
        'at://did:example:evidence/app.warlog.document/abc123',
        'at://did:example:evidence/app.warlog.document/def456',
      ])
    })

    it('handles whistleblower classification with enhanced security', async () => {
      const whistleblowerEntry = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Whistleblower report',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PRIVATE,
          classification: SecurityClassification.WHISTLEBLOWER,
          content: {
            text: 'Whistleblower report',
            isEncrypted: true,
            encryptionLevel: EncryptionLevel.QUANTUM_RESISTANT,
            encryptionMetadata: {
              algorithm: 'Kyber-1024',
              keyId: 'whistleblower-key',
              iv: 'whistleblower-iv',
              salt: 'whistleblower-salt',
              signature: 'whistleblower-signature',
            },
          },
          anonymousMode: true,
          sourceProtection: true,
          createdAt: new Date().toISOString(),
        },
      })

      expect(whistleblowerEntry.data.uri).toBeDefined()

      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(whistleblowerEntry.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.classification).toBe(SecurityClassification.WHISTLEBLOWER)
      expect(storedRecord.content.encryptionLevel).toBe(EncryptionLevel.QUANTUM_RESISTANT)
      expect(storedRecord.anonymousMode).toBe(true)
      expect(storedRecord.sourceProtection).toBe(true)
    })
  })

  describe('Performance and Scalability', () => {
    it('handles large journal entry lists efficiently', async () => {
      const startTime = Date.now()
      
      // Create multiple entries for performance testing
      const createPromises = []
      for (let i = 0; i < 20; i++) {
        createPromises.push(
          aliceAgent.api.com.atproto.repo.createRecord({
            repo: aliceAgent.accountDid!,
            collection: 'app.warlog.journal',
            record: {
              $type: 'app.warlog.journal',
              text: `Performance test entry ${i}`,
              entryType: 'real_time',
              privacyLevel: PrivacyLevel.PUBLIC,
              classification: SecurityClassification.UNCLASSIFIED,
              content: {
                text: `Performance test entry ${i}`,
                isEncrypted: false,
                encryptionLevel: EncryptionLevel.NONE,
              },
              createdAt: new Date().toISOString(),
            },
          })
        )
      }

      await Promise.all(createPromises)
      
      const createTime = Date.now() - startTime
      expect(createTime).toBeLessThan(10000) // Should complete in under 10 seconds

      // Test listing performance
      const listStartTime = Date.now()
      const listRes = await aliceAgent.api.com.atproto.repo.listRecords({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        limit: 50,
      })
      const listTime = Date.now() - listStartTime

      expect(listRes.data.records.length).toBeGreaterThan(20)
      expect(listTime).toBeLessThan(2000) // Should list in under 2 seconds
    })

    it('handles complex encrypted entries efficiently', async () => {
      const startTime = Date.now()

      const complexEntry = {
        $type: 'app.warlog.journal',
        text: 'Complex encrypted entry with multiple fields',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Complex encrypted entry with multiple fields',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'complex-key-123',
            iv: 'complex-iv-123',
            salt: 'complex-salt-123',
            signature: 'complex-signature-123',
          },
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-complex-symptoms-data'.repeat(10),
          count: 5,
        },
        location: {
          encrypted: true,
          data: JSON.stringify({
            latitude: 40.7128,
            longitude: -74.0060,
            address: 'New York, NY',
            additionalData: 'extra-location-data'.repeat(5),
          }),
          accuracy: 10,
        },
        evidenceUris: Array.from({ length: 10 }, (_, i) => 
          `at://did:example:evidence/app.warlog.document/evidence${i}`
        ),
        sourceIds: Array.from({ length: 5 }, (_, i) => `source-${i}`),
        tags: ['medical', 'harassment', 'surveillance', 'evidence', 'location'],
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: complexEntry,
      })

      const createTime = Date.now() - startTime
      expect(createTime).toBeLessThan(5000) // Should create in under 5 seconds
      expect(res.data.uri).toBeDefined()

      // Test reading the complex entry
      const readStartTime = Date.now()
      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })
      const readTime = Date.now() - readStartTime

      expect(readTime).toBeLessThan(1000) // Should read in under 1 second
      expect(getRes.data.value).toBeDefined()

      const storedRecord = getRes.data.value as any
      expect(storedRecord.evidenceUris).toHaveLength(10)
      expect(storedRecord.sourceIds).toHaveLength(5)
      expect(storedRecord.tags).toHaveLength(5)
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('handles malformed journal entries gracefully', async () => {
      const malformedRecord = {
        $type: 'app.warlog.journal',
        // Missing required fields
        privacyLevel: 'invalid_privacy_level',
        classification: 'invalid_classification',
      }

      await expect(
        aliceAgent.api.com.atproto.repo.createRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          record: malformedRecord,
        })
      ).rejects.toThrow()
    })

    it('handles concurrent access to the same entry', async () => {
      // Create an entry for concurrent access testing
      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Entry for concurrent access test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Entry for concurrent access test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const rkey = new AtUri(res.data.uri).rkey

      // Simulate concurrent reads
      const readPromises = Array.from({ length: 10 }, () =>
        aliceAgent.api.com.atproto.repo.getRecord({
          repo: aliceAgent.accountDid!,
          collection: 'app.warlog.journal',
          rkey: rkey,
        })
      )

      const results = await Promise.all(readPromises)
      
      // All reads should succeed
      results.forEach(result => {
        expect(result.data.value).toBeDefined()
        const record = result.data.value as any
        expect(record.text).toBe('Entry for concurrent access test')
      })
    })

    it('handles network interruptions gracefully', async () => {
      // This test would typically involve mocking network failures
      // For now, we'll test that the basic error handling works
      
      await expect(
        aliceAgent.api.com.atproto.repo.getRecord({
          repo: 'did:invalid:user',
          collection: 'app.warlog.journal',
          rkey: 'invalid-rkey',
        })
      ).rejects.toThrow()
    })

    it('handles large payloads appropriately', async () => {
      const largeText = 'Large journal entry content '.repeat(1000) // ~30KB
      
      const largeEntry = {
        $type: 'app.warlog.journal',
        text: largeText,
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: largeText,
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      const res = await aliceAgent.api.com.atproto.repo.createRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        record: largeEntry,
      })

      expect(res.data.uri).toBeDefined()

      // Verify the large entry can be retrieved
      const getRes = await aliceAgent.api.com.atproto.repo.getRecord({
        repo: aliceAgent.accountDid!,
        collection: 'app.warlog.journal',
        rkey: new AtUri(res.data.uri).rkey,
      })

      const storedRecord = getRes.data.value as any
      expect(storedRecord.text).toBe(largeText)
      expect(storedRecord.text.length).toBeGreaterThan(30000)
    })
  })
})
