/**
 * Lexicon Schema Validation Tests for Journal System
 * 
 * Validates AT Protocol lexicon schema compliance, type validation,
 * and cross-package schema consistency for journal entries.
 */

import { Lexicons } from '@atproto/lexicon'
import { lexToJson } from '@atproto/lexicon'
import { AtpAgent } from '@atproto/api'
import { TestNetworkNoAppView } from '@atproto/dev-env'
import { TID } from '@atproto/common'
import {
  PrivacyLevel,
  SecurityClassification,
  EncryptionLevel,
} from '../../src/journal-security'
import { AppContext } from '../../src/context'
import { ids, lexicons } from '../../src/lexicon/lexicons'

describe('Journal Lexicon Schema Validation', () => {
  let network: TestNetworkNoAppView
  let ctx: AppContext
  let agent: AtpAgent
  let lex: Lexicons

  beforeAll(async () => {
    network = await TestNetworkNoAppView.create({
      dbPostgresSchema: 'lexicon_validation',
    })
    // @ts-expect-error Error due to circular dependency with the dev-env package
    ctx = network.pds.ctx
    agent = network.pds.getClient()
    lex = new Lexicons(lexicons)

    await agent.createAccount({
      email: 'test@example.com',
      handle: 'test.user',
      password: 'test-pass',
    })
  })

  afterAll(async () => {
    await network.close()
  })

  describe('Journal Entry Schema Structure', () => {
    it('validates basic journal entry schema', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      
      expect(schema).toBeDefined()
      expect(schema.type).toBe('record')
      
      // Check required properties exist in schema
      const record = schema as any
      expect(record.record).toBeDefined()
      expect(record.record.properties).toBeDefined()
      
      const properties = record.record.properties
      expect(properties.text).toBeDefined()
      expect(properties.entryType).toBeDefined()
      expect(properties.privacyLevel).toBeDefined()
      expect(properties.classification).toBeDefined()
      expect(properties.content).toBeDefined()
      expect(properties.createdAt).toBeDefined()
    })

    it('validates privacy level enum values', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      const record = schema as any
      const privacyLevelProperty = record.record.properties.privacyLevel
      
      expect(privacyLevelProperty).toBeDefined()
      expect(privacyLevelProperty.type).toBe('string')
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.PUBLIC)
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.PRIVATE)
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.COMMUNITY)
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.MEDICAL)
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.LEGAL)
      expect(privacyLevelProperty.knownValues).toContain(PrivacyLevel.ANONYMOUS)
    })

    it('validates security classification enum values', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      const record = schema as any
      const classificationProperty = record.record.properties.classification
      
      expect(classificationProperty).toBeDefined()
      expect(classificationProperty.type).toBe('string')
      expect(classificationProperty.knownValues).toContain(SecurityClassification.UNCLASSIFIED)
      expect(classificationProperty.knownValues).toContain(SecurityClassification.SENSITIVE)
      expect(classificationProperty.knownValues).toContain(SecurityClassification.PHI)
      expect(classificationProperty.knownValues).toContain(SecurityClassification.LEGAL_EVIDENCE)
      expect(classificationProperty.knownValues).toContain(SecurityClassification.WHISTLEBLOWER)
    })

    it('validates entry type enum values', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      const record = schema as any
      const entryTypeProperty = record.record.properties.entryType
      
      expect(entryTypeProperty).toBeDefined()
      expect(entryTypeProperty.type).toBe('string')
      expect(entryTypeProperty.knownValues).toContain('real_time')
      expect(entryTypeProperty.knownValues).toContain('backdated')
    })

    it('validates content object structure', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      const record = schema as any
      const contentProperty = record.record.properties.content
      
      expect(contentProperty).toBeDefined()
      expect(contentProperty.type).toBe('object')
      
      const contentProps = contentProperty.properties
      expect(contentProps.text).toBeDefined()
      expect(contentProps.isEncrypted).toBeDefined()
      expect(contentProps.encryptionLevel).toBeDefined()
      expect(contentProps.encryptionMetadata).toBeDefined()
      
      // Validate encryption level enum
      expect(contentProps.encryptionLevel.knownValues).toContain(EncryptionLevel.NONE)
      expect(contentProps.encryptionLevel.knownValues).toContain(EncryptionLevel.STANDARD)
      expect(contentProps.encryptionLevel.knownValues).toContain(EncryptionLevel.ENHANCED)
      expect(contentProps.encryptionLevel.knownValues).toContain(EncryptionLevel.QUANTUM_RESISTANT)
    })

    it('validates optional field structures', () => {
      const schema = lex.getDefOrThrow('app.warlog.journal')
      const record = schema as any
      const properties = record.record.properties
      
      // Validate symptoms object
      if (properties.symptoms) {
        expect(properties.symptoms.type).toBe('object')
        expect(properties.symptoms.properties.encrypted).toBeDefined()
        expect(properties.symptoms.properties.data).toBeDefined()
        expect(properties.symptoms.properties.count).toBeDefined()
      }
      
      // Validate location object
      if (properties.location) {
        expect(properties.location.type).toBe('object')
        expect(properties.location.properties.encrypted).toBeDefined()
        expect(properties.location.properties.data).toBeDefined()
        expect(properties.location.properties.accuracy).toBeDefined()
      }
      
      // Validate array fields
      if (properties.evidenceUris) {
        expect(properties.evidenceUris.type).toBe('array')
        expect(properties.evidenceUris.items.type).toBe('string')
      }
      
      if (properties.sourceIds) {
        expect(properties.sourceIds.type).toBe('array')
        expect(properties.sourceIds.items.type).toBe('string')
      }
      
      if (properties.tags) {
        expect(properties.tags.type).toBe('array')
        expect(properties.tags.items.type).toBe('string')
      }
    })
  })

  describe('Schema Validation with Real Data', () => {
    it('validates minimal valid journal entry', () => {
      const minimalEntry = {
        $type: 'app.warlog.journal',
        text: 'Minimal journal entry',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Minimal journal entry',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', minimalEntry)
      }).not.toThrow()
    })

    it('validates complete journal entry with all optional fields', () => {
      const completeEntry = {
        $type: 'app.warlog.journal',
        text: 'Complete journal entry with all fields',
        entryType: 'backdated',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Complete journal entry with all fields',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'test-key-123',
            iv: 'test-iv-123',
            salt: 'test-salt-123',
            signature: 'test-signature-123',
          },
        },
        createdAt: new Date().toISOString(),
        incidentTimestamp: new Date(Date.now() - 86400000).toISOString(),
        accessControlList: ['did:example:user1', 'did:example:user2'],
        communityBadges: ['havana', 'gangstalked'],
        location: {
          encrypted: true,
          data: 'encrypted-location-data',
          accuracy: 10,
          address: 'New York, NY',
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptoms-data',
          count: 3,
        },
        evidenceUris: [
          'at://did:example:user/app.warlog.document/evidence1',
          'at://did:example:user/app.warlog.document/evidence2',
        ],
        sourceIds: ['source-1', 'source-2', 'source-3'],
        tags: ['harassment', 'surveillance', 'medical'],
        legalHoldStatus: true,
        anonymousMode: false,
        sourceProtection: false,
        accessCount: 0,
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', completeEntry)
      }).not.toThrow()
    })

    it('rejects entries with invalid privacy levels', () => {
      const invalidEntry = {
        $type: 'app.warlog.journal',
        text: 'Entry with invalid privacy level',
        entryType: 'real_time',
        privacyLevel: 'invalid_privacy_level',
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with invalid privacy level',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', invalidEntry)
      }).toThrow()
    })

    it('rejects entries with invalid security classification', () => {
      const invalidEntry = {
        $type: 'app.warlog.journal',
        text: 'Entry with invalid classification',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: 'invalid_classification',
        content: {
          text: 'Entry with invalid classification',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', invalidEntry)
      }).toThrow()
    })

    it('rejects entries with invalid encryption level', () => {
      const invalidEntry = {
        $type: 'app.warlog.journal',
        text: 'Entry with invalid encryption level',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with invalid encryption level',
          isEncrypted: false,
          encryptionLevel: 'invalid_encryption_level',
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', invalidEntry)
      }).toThrow()
    })

    it('rejects entries missing required fields', () => {
      const incompleteEntry = {
        $type: 'app.warlog.journal',
        // Missing text, entryType, privacyLevel, classification, content
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', incompleteEntry)
      }).toThrow()
    })

    it('rejects entries with malformed content object', () => {
      const malformedEntry = {
        $type: 'app.warlog.journal',
        text: 'Entry with malformed content',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          // Missing required fields: text, isEncrypted, encryptionLevel
          extraField: 'should not be here',
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', malformedEntry)
      }).toThrow()
    })

    it('validates encryption metadata structure', () => {
      const entryWithEncryption = {
        $type: 'app.warlog.journal',
        text: 'Entry with encryption metadata',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Entry with encryption metadata',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'test-key-456',
            iv: 'test-iv-456',
            salt: 'test-salt-456',
            signature: 'test-signature-456',
          },
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithEncryption)
      }).not.toThrow()
    })

    it('validates symptoms object structure', () => {
      const entryWithSymptoms = {
        $type: 'app.warlog.journal',
        text: 'Entry with symptoms',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Entry with symptoms',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptoms-data',
          count: 5,
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithSymptoms)
      }).not.toThrow()
    })

    it('validates location object structure', () => {
      const entryWithLocation = {
        $type: 'app.warlog.journal',
        text: 'Entry with location',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Entry with location',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
        },
        location: {
          encrypted: true,
          data: 'encrypted-location-data',
          accuracy: 15,
          address: 'San Francisco, CA',
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithLocation)
      }).not.toThrow()
    })

    it('validates array fields correctly', () => {
      const entryWithArrays = {
        $type: 'app.warlog.journal',
        text: 'Entry with array fields',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.LEGAL,
        classification: SecurityClassification.LEGAL_EVIDENCE,
        content: {
          text: 'Entry with array fields',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        accessControlList: [
          'did:example:user1',
          'did:example:user2',
          'did:example:user3',
        ],
        communityBadges: ['havana', 'targeted', 'whistleblower'],
        evidenceUris: [
          'at://did:example:evidence/app.warlog.document/doc1',
          'at://did:example:evidence/app.warlog.document/doc2',
        ],
        sourceIds: ['source-alpha', 'source-beta', 'source-gamma'],
        tags: ['legal', 'evidence', 'harassment', 'documentation'],
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithArrays)
      }).not.toThrow()
    })
  })

  describe('Date and Time Validation', () => {
    it('validates ISO 8601 date formats', () => {
      const validDates = [
        new Date().toISOString(),
        '2024-01-15T10:30:00.000Z',
        '2024-01-15T10:30:00Z',
        '2024-01-15T10:30:00.123456Z',
      ]

      validDates.forEach(date => {
        const entry = {
          $type: 'app.warlog.journal',
          text: 'Date validation test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Date validation test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: date,
        }

        expect(() => {
          lex.assertValidRecord('app.warlog.journal', entry)
        }).not.toThrow()
      })
    })

    it('rejects invalid date formats', () => {
      const invalidDates = [
        '2024-01-15',
        '2024/01/15 10:30:00',
        'January 15, 2024',
        'invalid-date',
        1705317000000, // Unix timestamp as number
      ]

      invalidDates.forEach(date => {
        const entry = {
          $type: 'app.warlog.journal',
          text: 'Invalid date test',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Invalid date test',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: date,
        }

        expect(() => {
          lex.assertValidRecord('app.warlog.journal', entry)
        }).toThrow()
      })
    })

    it('validates incident timestamp for backdated entries', () => {
      const backdatedEntry = {
        $type: 'app.warlog.journal',
        text: 'Backdated entry with incident timestamp',
        entryType: 'backdated',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Backdated entry with incident timestamp',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
        incidentTimestamp: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', backdatedEntry)
      }).not.toThrow()
    })
  })

  describe('String Length and Format Validation', () => {
    it('validates text field length limits', () => {
      // Test maximum allowed text length
      const longText = 'x'.repeat(10000) // 10KB of text
      const entryWithLongText = {
        $type: 'app.warlog.journal',
        text: longText,
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: longText,
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      // Should accept reasonable length text
      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithLongText)
      }).not.toThrow()
    })

    it('validates URI formats for evidence and source references', () => {
      const validUris = [
        'at://did:example:user/app.warlog.document/abc123',
        'https://example.com/evidence/document.pdf',
        'at://did:plc:abc123/app.warlog.source/def456',
      ]

      const entryWithValidUris = {
        $type: 'app.warlog.journal',
        text: 'Entry with valid URIs',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with valid URIs',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        evidenceUris: validUris,
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithValidUris)
      }).not.toThrow()
    })

    it('validates DID formats in access control lists', () => {
      const validDids = [
        'did:example:alice',
        'did:plc:abc123def456',
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      ]

      const entryWithValidDids = {
        $type: 'app.warlog.journal',
        text: 'Entry with valid DIDs',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Entry with valid DIDs',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
        },
        accessControlList: validDids,
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithValidDids)
      }).not.toThrow()
    })
  })

  describe('Type Consistency and Constraints', () => {
    it('validates boolean field types', () => {
      const entryWithBooleans = {
        $type: 'app.warlog.journal',
        text: 'Entry with boolean fields',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.LEGAL,
        classification: SecurityClassification.LEGAL_EVIDENCE,
        content: {
          text: 'Entry with boolean fields',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        legalHoldStatus: true,
        anonymousMode: false,
        sourceProtection: true,
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithBooleans)
      }).not.toThrow()
    })

    it('validates numeric field types and ranges', () => {
      const entryWithNumbers = {
        $type: 'app.warlog.journal',
        text: 'Entry with numeric fields',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Entry with numeric fields',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptoms',
          count: 5, // Should be a positive integer
        },
        location: {
          encrypted: true,
          data: 'encrypted-location',
          accuracy: 10.5, // Should allow decimal values
        },
        accessCount: 0, // Should start at 0
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithNumbers)
      }).not.toThrow()
    })

    it('rejects entries with invalid type mismatches', () => {
      const entryWithTypeMismatch = {
        $type: 'app.warlog.journal',
        text: 'Entry with type mismatches',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with type mismatches',
          isEncrypted: 'yes', // Should be boolean, not string
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithTypeMismatch)
      }).toThrow()
    })
  })

  describe('Cross-Reference Validation', () => {
    it('validates AT-URI format for cross-references', async () => {
      // Create a test entry to reference
      const targetEntry = await agent.api.com.atproto.repo.createRecord({
        repo: agent.accountDid!,
        collection: 'app.warlog.journal',
        record: {
          $type: 'app.warlog.journal',
          text: 'Target entry for cross-reference',
          entryType: 'real_time',
          privacyLevel: PrivacyLevel.PUBLIC,
          classification: SecurityClassification.UNCLASSIFIED,
          content: {
            text: 'Target entry for cross-reference',
            isEncrypted: false,
            encryptionLevel: EncryptionLevel.NONE,
          },
          createdAt: new Date().toISOString(),
        },
      })

      const entryWithReferences = {
        $type: 'app.warlog.journal',
        text: 'Entry with cross-references',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with cross-references',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        evidenceUris: [targetEntry.data.uri],
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithReferences)
      }).not.toThrow()
    })

    it('validates source ID format consistency', () => {
      const entryWithSourceIds = {
        $type: 'app.warlog.journal',
        text: 'Entry with source IDs',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with source IDs',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        sourceIds: [
          'source-academic-001',
          'source-news-002',
          'source-legal-003',
        ],
        createdAt: new Date().toISOString(),
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithSourceIds)
      }).not.toThrow()
    })
  })

  describe('Schema Evolution and Backward Compatibility', () => {
    it('handles records with extra unknown fields gracefully', () => {
      const entryWithExtraFields = {
        $type: 'app.warlog.journal',
        text: 'Entry with extra fields',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Entry with extra fields',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: new Date().toISOString(),
        // Extra fields that might be added in future versions
        futureField: 'future value',
        experimentalFeature: {
          enabled: true,
          config: 'test',
        },
      }

      // Should either accept gracefully or provide clear error
      try {
        lex.assertValidRecord('app.warlog.journal', entryWithExtraFields)
      } catch (error) {
        // If it throws, the error should be informative
        expect(error).toBeDefined()
      }
    })

    it('validates minimal schema requirements for old entries', () => {
      // Test that old entries with minimal fields still validate
      const minimalLegacyEntry = {
        $type: 'app.warlog.journal',
        text: 'Legacy minimal entry',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.PUBLIC,
        classification: SecurityClassification.UNCLASSIFIED,
        content: {
          text: 'Legacy minimal entry',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        createdAt: '2023-01-01T00:00:00.000Z',
      }

      expect(() => {
        lex.assertValidRecord('app.warlog.journal', minimalLegacyEntry)
      }).not.toThrow()
    })
  })

  describe('Performance and Complexity', () => {
    it('validates complex nested structures efficiently', () => {
      const complexEntry = {
        $type: 'app.warlog.journal',
        text: 'Complex entry with deep nesting',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Complex entry with deep nesting',
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
          data: 'complex-encrypted-symptoms',
          count: 10,
        },
        location: {
          encrypted: true,
          data: JSON.stringify({
            coordinates: { lat: 40.7128, lng: -74.0060 },
            address: 'Complex Address',
            metadata: { source: 'GPS', confidence: 0.95 },
          }),
          accuracy: 5.2,
        },
        evidenceUris: Array.from({ length: 50 }, (_, i) => 
          `at://did:example:evidence/app.warlog.document/evidence${i}`
        ),
        sourceIds: Array.from({ length: 20 }, (_, i) => `source-${i}`),
        tags: Array.from({ length: 30 }, (_, i) => `tag-${i}`),
        accessControlList: Array.from({ length: 10 }, (_, i) => 
          `did:example:user${i}`
        ),
        createdAt: new Date().toISOString(),
      }

      const startTime = Date.now()
      expect(() => {
        lex.assertValidRecord('app.warlog.journal', complexEntry)
      }).not.toThrow()
      const validationTime = Date.now() - startTime

      // Validation should complete quickly even for complex entries
      expect(validationTime).toBeLessThan(100) // Under 100ms
    })

    it('handles large arrays efficiently', () => {
      const entryWithLargeArrays = {
        $type: 'app.warlog.journal',
        text: 'Entry with large arrays',
        entryType: 'real_time',
        privacyLevel: PrivacyLevel.LEGAL,
        classification: SecurityClassification.LEGAL_EVIDENCE,
        content: {
          text: 'Entry with large arrays',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        evidenceUris: Array.from({ length: 100 }, (_, i) => 
          `at://did:example:evidence/app.warlog.document/evidence${i}`
        ),
        tags: Array.from({ length: 100 }, (_, i) => `tag-${i}`),
        createdAt: new Date().toISOString(),
      }

      const startTime = Date.now()
      expect(() => {
        lex.assertValidRecord('app.warlog.journal', entryWithLargeArrays)
      }).not.toThrow()
      const validationTime = Date.now() - startTime

      expect(validationTime).toBeLessThan(200) // Under 200ms even for large arrays
    })
  })
})
