/**
 * Test suite for HIPAAComplianceManager
 * 
 * Validates HIPAA compliance requirements for journal entries including
 * PHI access logging, compliance validation, and breach notification assessment.
 */

import { describe, expect, it, jest, beforeEach, afterEach } from '@jest/globals'
import {
  HIPAAComplianceManager,
  SecurityContext,
  SecureJournalEntry,
  SecurityClassification,
  PrivacyLevel,
  EncryptionLevel,
  AuditLogEntry,
} from '../../src/journal-security'

// Mock logger to capture audit logs
const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
}

jest.mock('#/logger', () => ({
  logger: mockLogger,
}))

describe('HIPAAComplianceManager', () => {
  let hipaaManager: HIPAAComplianceManager
  let mockSecurityContext: SecurityContext
  let mockPHIEntry: SecureJournalEntry
  let mockPublicEntry: SecureJournalEntry

  beforeEach(() => {
    // Get singleton instance
    hipaaManager = HIPAAComplianceManager.getInstance()
    
    // Clear any existing audit logs
    ;(hipaaManager as any).auditLog = []
    
    // Mock security context
    mockSecurityContext = {
      userDid: 'did:example:alice',
      sessionId: 'session-123',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Test Browser)',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access'],
    }

    // Mock PHI journal entry
    mockPHIEntry = {
      uri: 'at://did:example:alice/app.warlog.journal/phi123',
      cid: 'bafkreiphiexample123',
      author: {
        did: 'did:example:alice',
        handle: 'alice.test',
        displayName: 'Alice Test',
      },
      content: {
        text: 'Encrypted medical symptoms',
        isEncrypted: true,
        encryptionLevel: EncryptionLevel.ENHANCED,
        encryptionMetadata: {
          algorithm: 'AES-256-CBC',
          keyId: 'key-123',
          iv: 'iv-123',
          salt: 'salt-123',
          signature: 'sig-123',
        },
      },
      entryType: 'real_time',
      createdAt: '2024-01-15T10:30:00Z',
      privacyLevel: PrivacyLevel.MEDICAL,
      classification: SecurityClassification.PHI,
      symptoms: {
        encrypted: true,
        data: 'encrypted-symptoms-data',
        count: 3,
      },
      accessCount: 0,
    }

    // Mock public journal entry
    mockPublicEntry = {
      uri: 'at://did:example:alice/app.warlog.journal/public123',
      cid: 'bafkreipublicexample123',
      author: {
        did: 'did:example:alice',
        handle: 'alice.test',
        displayName: 'Alice Test',
      },
      content: {
        text: 'Public incident report',
        isEncrypted: false,
        encryptionLevel: EncryptionLevel.NONE,
      },
      entryType: 'real_time',
      createdAt: '2024-01-15T10:30:00Z',
      privacyLevel: PrivacyLevel.PUBLIC,
      classification: SecurityClassification.UNCLASSIFIED,
      accessCount: 0,
    }

    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('PHI Access Logging', () => {
    it('should log PHI access with all required information', async () => {
      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(1)

      const logEntry = auditLog[0]
      expect(logEntry).toMatchObject({
        userDid: mockSecurityContext.userDid,
        action: 'read',
        resourceUri: mockPHIEntry.uri,
        classification: SecurityClassification.PHI,
        privacyLevel: PrivacyLevel.MEDICAL,
        ipAddress: mockSecurityContext.ipAddress,
        userAgent: mockSecurityContext.userAgent,
        sessionId: mockSecurityContext.sessionId,
        success: true,
        metadata: {
          authLevel: mockSecurityContext.authLevel,
          permissions: mockSecurityContext.permissions,
        },
      })

      expect(logEntry.id).toBeDefined()
      expect(logEntry.timestamp).toBeGreaterThan(0)
      expect(mockLogger.info).toHaveBeenCalledWith('PHI access logged', {
        userDid: mockSecurityContext.userDid,
        action: 'read',
        resourceUri: mockPHIEntry.uri,
        success: true,
      })
    })

    it('should log failed PHI access attempts', async () => {
      const errorMessage = 'Access denied due to insufficient permissions'

      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        false,
        errorMessage
      )

      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(1)

      const logEntry = auditLog[0]
      expect(logEntry.success).toBe(false)
      expect(logEntry.errorMessage).toBe(errorMessage)
    })

    it('should generate unique audit log entry IDs', async () => {
      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        'at://another/uri',
        'write',
        true
      )

      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(2)
      expect(auditLog[0].id).not.toBe(auditLog[1].id)
    })

    it('should handle missing optional context information', async () => {
      const minimalContext: SecurityContext = {
        userDid: 'did:example:bob',
        sessionId: 'session-456',
        authLevel: 'basic',
        permissions: [],
      }

      await hipaaManager.logPHIAccess(
        minimalContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(1)

      const logEntry = auditLog[0]
      expect(logEntry.ipAddress).toBeUndefined()
      expect(logEntry.userAgent).toBeUndefined()
      expect(logEntry.userDid).toBe(minimalContext.userDid)
    })
  })

  describe('HIPAA Compliance Validation', () => {
    it('should validate compliant PHI entry', () => {
      const result = hipaaManager.validateHIPAACompliance(mockPHIEntry)

      expect(result.isCompliant).toBe(true)
      expect(result.violations).toHaveLength(0)
      expect(result.recommendations).toEqual(
        expect.arrayContaining([
          expect.stringContaining('legal hold')
        ])
      )
    })

    it('should detect unencrypted PHI content violation', () => {
      const nonCompliantEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        content: {
          text: 'Unencrypted PHI content',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
      }

      const result = hipaaManager.validateHIPAACompliance(nonCompliantEntry)

      expect(result.isCompliant).toBe(false)
      expect(result.violations).toContain('PHI content must be encrypted')
    })

    it('should detect unencrypted symptoms violation', () => {
      const nonCompliantEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        symptoms: {
          encrypted: false,
          data: 'Unencrypted symptoms',
          count: 2,
        },
      }

      const result = hipaaManager.validateHIPAACompliance(nonCompliantEntry)

      expect(result.isCompliant).toBe(false)
      expect(result.violations).toContain('Symptom data must be encrypted')
    })

    it('should detect public privacy level violation for PHI', () => {
      const nonCompliantEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        privacyLevel: PrivacyLevel.PUBLIC,
      }

      const result = hipaaManager.validateHIPAACompliance(nonCompliantEntry)

      expect(result.isCompliant).toBe(false)
      expect(result.violations).toContain('PHI cannot have public privacy level')
    })

    it('should recommend location encryption for sensitive data', () => {
      const entryWithLocation: SecureJournalEntry = {
        ...mockPHIEntry,
        classification: SecurityClassification.SENSITIVE,
        location: {
          encrypted: false,
          data: JSON.stringify({ latitude: 40.7128, longitude: -74.0060 }),
          accuracy: 10,
        },
      }

      const result = hipaaManager.validateHIPAACompliance(entryWithLocation)

      expect(result.isCompliant).toBe(true)
      expect(result.recommendations).toContain('Consider encrypting location data')
    })

    it('should recommend legal hold for legal evidence', () => {
      const legalEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        classification: SecurityClassification.LEGAL_EVIDENCE,
      }

      const result = hipaaManager.validateHIPAACompliance(legalEntry)

      expect(result.recommendations).toContain('Ensure legal hold policies are applied')
    })

    it('should validate non-PHI entries as compliant', () => {
      const result = hipaaManager.validateHIPAACompliance(mockPublicEntry)

      expect(result.isCompliant).toBe(true)
      expect(result.violations).toHaveLength(0)
    })

    it('should detect multiple violations', () => {
      const multipleViolationsEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        content: {
          text: 'Unencrypted PHI',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        symptoms: {
          encrypted: false,
          data: 'Unencrypted symptoms',
          count: 1,
        },
        privacyLevel: PrivacyLevel.PUBLIC,
      }

      const result = hipaaManager.validateHIPAACompliance(multipleViolationsEntry)

      expect(result.isCompliant).toBe(false)
      expect(result.violations).toHaveLength(3)
      expect(result.violations).toEqual(
        expect.arrayContaining([
          'PHI content must be encrypted',
          'Symptom data must be encrypted',
          'PHI cannot have public privacy level',
        ])
      )
    })
  })

  describe('Breach Notification Assessment', () => {
    beforeEach(() => {
      // Mock the private method getPHIEntries
      jest.spyOn(hipaaManager as any, 'getPHIEntries').mockImplementation(
        async (uris: string[]) => {
          // Return PHI entries for uris that contain 'phi'
          return uris
            .filter(uri => uri.includes('phi'))
            .map(uri => ({ ...mockPHIEntry, uri }))
        }
      )
    })

    it('should not require notification for non-PHI breaches', async () => {
      const affectedEntries = [
        'at://did:example:alice/app.warlog.journal/public123',
        'at://did:example:alice/app.warlog.journal/community456',
      ]

      const result = await hipaaManager.assessBreachNotification(
        affectedEntries,
        'unauthorized_access',
        mockSecurityContext
      )

      expect(result.notificationRequired).toBe(false)
      expect(result.timeframe).toBe(0)
      expect(result.authorities).toHaveLength(0)
      expect(result.users).toHaveLength(0)
    })

    it('should require notification for PHI breaches', async () => {
      const affectedEntries = [
        'at://did:example:alice/app.warlog.journal/phi123',
        'at://did:example:bob/app.warlog.journal/phi456',
      ]

      const result = await hipaaManager.assessBreachNotification(
        affectedEntries,
        'data_loss',
        mockSecurityContext
      )

      expect(result.notificationRequired).toBe(true)
      expect(result.timeframe).toBe(72) // 72 hours as per HIPAA
      expect(result.authorities).toEqual(['HHS', 'State Attorney General'])
      expect(result.users).toHaveLength(2)
    })

    it('should handle mixed PHI and non-PHI breaches', async () => {
      const affectedEntries = [
        'at://did:example:alice/app.warlog.journal/phi123',
        'at://did:example:alice/app.warlog.journal/public456',
        'at://did:example:bob/app.warlog.journal/phi789',
      ]

      const result = await hipaaManager.assessBreachNotification(
        affectedEntries,
        'system_compromise',
        mockSecurityContext
      )

      expect(result.notificationRequired).toBe(true)
      expect(result.timeframe).toBe(72)
      expect(result.users).toHaveLength(2) // Only PHI entries
    })

    it('should handle different breach types', async () => {
      const affectedEntries = ['at://did:example:alice/app.warlog.journal/phi123']

      const breachTypes = ['unauthorized_access', 'data_loss', 'system_compromise'] as const

      for (const breachType of breachTypes) {
        const result = await hipaaManager.assessBreachNotification(
          affectedEntries,
          breachType,
          mockSecurityContext
        )

        expect(result.notificationRequired).toBe(true)
        expect(result.timeframe).toBe(72)
        expect(result.authorities).toEqual(['HHS', 'State Attorney General'])
      }
    })
  })

  describe('Singleton Pattern', () => {
    it('should return the same instance', () => {
      const instance1 = HIPAAComplianceManager.getInstance()
      const instance2 = HIPAAComplianceManager.getInstance()

      expect(instance1).toBe(instance2)
    })

    it('should maintain state across getInstance calls', async () => {
      const instance1 = HIPAAComplianceManager.getInstance()
      
      await instance1.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      const instance2 = HIPAAComplianceManager.getInstance()
      const auditLog = (instance2 as any).auditLog as AuditLogEntry[]

      expect(auditLog).toHaveLength(1)
    })
  })

  describe('Audit Log Persistence', () => {
    it('should call persistAuditLog in development environment', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'development'

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      expect(consoleSpy).toHaveBeenCalledWith(
        'AUDIT LOG:',
        expect.objectContaining({
          userDid: mockSecurityContext.userDid,
          action: 'read',
          resourceUri: mockPHIEntry.uri,
        })
      )

      consoleSpy.mockRestore()
      process.env.NODE_ENV = originalEnv
    })

    it('should not log to console in production environment', async () => {
      const originalEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      await hipaaManager.logPHIAccess(
        mockSecurityContext,
        mockPHIEntry.uri,
        'read',
        true
      )

      expect(consoleSpy).not.toHaveBeenCalled()

      consoleSpy.mockRestore()
      process.env.NODE_ENV = originalEnv
    })
  })

  describe('Error Handling', () => {
    it('should handle invalid security context gracefully', async () => {
      const invalidContext = {} as SecurityContext

      await expect(
        hipaaManager.logPHIAccess(
          invalidContext,
          mockPHIEntry.uri,
          'read',
          true
        )
      ).resolves.not.toThrow()

      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(1)
    })

    it('should handle empty affected entries in breach assessment', async () => {
      const result = await hipaaManager.assessBreachNotification(
        [],
        'unauthorized_access',
        mockSecurityContext
      )

      expect(result.notificationRequired).toBe(false)
    })

    it('should validate entries with missing required fields', () => {
      const incompleteEntry = {
        uri: 'test-uri',
        classification: SecurityClassification.PHI,
      } as SecureJournalEntry

      const result = hipaaManager.validateHIPAACompliance(incompleteEntry)

      // Should handle gracefully without throwing
      expect(result).toBeDefined()
      expect(result.isCompliant).toBeDefined()
      expect(result.violations).toBeDefined()
      expect(result.recommendations).toBeDefined()
    })
  })

  describe('Performance and Memory', () => {
    it('should handle large numbers of audit log entries', async () => {
      const startTime = Date.now()

      // Create 1000 audit log entries
      for (let i = 0; i < 1000; i++) {
        await hipaaManager.logPHIAccess(
          mockSecurityContext,
          `${mockPHIEntry.uri}-${i}`,
          'read',
          true
        )
      }

      const endTime = Date.now()
      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]

      expect(auditLog).toHaveLength(1000)
      expect(endTime - startTime).toBeLessThan(5000) // Should complete in under 5 seconds
    })

    it('should validate complex entries efficiently', () => {
      const complexEntry: SecureJournalEntry = {
        ...mockPHIEntry,
        symptoms: {
          encrypted: true,
          data: 'complex-symptom-data'.repeat(100),
          count: 50,
        },
        location: {
          encrypted: true,
          data: JSON.stringify({
            latitude: 40.7128,
            longitude: -74.0060,
            additional: 'data'.repeat(100),
          }),
        },
        evidenceUris: Array.from({ length: 100 }, (_, i) => `evidence-${i}`),
        sourceIds: Array.from({ length: 50 }, (_, i) => `source-${i}`),
        tags: Array.from({ length: 20 }, (_, i) => `tag-${i}`),
      }

      const startTime = Date.now()
      const result = hipaaManager.validateHIPAACompliance(complexEntry)
      const endTime = Date.now()

      expect(result).toBeDefined()
      expect(endTime - startTime).toBeLessThan(100) // Should validate quickly
    })
  })
})