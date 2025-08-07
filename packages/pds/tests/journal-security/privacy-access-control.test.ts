/**
 * Test suite for PrivacyAccessControlManager
 * 
 * Validates multi-tier privacy controls for journal entries including
 * access level enforcement, badge verification, and permission checks.
 */

import { describe, expect, it, jest, beforeEach, afterEach } from '@jest/globals'
import {
  PrivacyAccessControlManager,
  SecurityContext,
  SecureJournalEntry,
  SecurityClassification,
  PrivacyLevel,
  EncryptionLevel,
} from '../../src/journal-security'

describe('PrivacyAccessControlManager', () => {
  let accessManager: PrivacyAccessControlManager
  let mockSecurityContext: SecurityContext
  let mockOwnerContext: SecurityContext
  let mockJournalEntry: SecureJournalEntry

  // Mock user badges for testing community access
  const mockUserBadges = [
    { type: 'havana', verified: true },
    { type: 'gangstalked', verified: true },
    { type: 'targeted', verified: false },
  ]

  const mockEntryBadges = ['havana', 'surveillance']

  beforeEach(() => {
    accessManager = new PrivacyAccessControlManager()

    // Mock base security context
    mockSecurityContext = {
      userDid: 'did:example:bob',
      sessionId: 'session-123',
      ipAddress: '192.168.1.1',
      userAgent: 'Mozilla/5.0 (Test Browser)',
      authLevel: 'mfa',
      permissions: ['basic:read'],
    }

    // Mock owner security context
    mockOwnerContext = {
      ...mockSecurityContext,
      userDid: 'did:example:alice',
      permissions: ['medical:read', 'phi:access', 'legal:evidence:access'],
    }

    // Mock journal entry
    mockJournalEntry = {
      uri: 'at://did:example:alice/app.warlog.journal/test123',
      cid: 'bafkreitestexample123',
      author: {
        did: 'did:example:alice',
        handle: 'alice.test',
        displayName: 'Alice Test',
      },
      content: {
        text: 'Test journal entry',
        isEncrypted: false,
        encryptionLevel: EncryptionLevel.NONE,
      },
      entryType: 'real_time',
      createdAt: '2024-01-15T10:30:00Z',
      privacyLevel: PrivacyLevel.PUBLIC,
      classification: SecurityClassification.UNCLASSIFIED,
      accessCount: 0,
    }

    // Mock private methods
    jest.spyOn(accessManager as any, 'getUserBadges').mockResolvedValue(mockUserBadges)
    jest.spyOn(accessManager as any, 'getEntryRelatedBadges').mockResolvedValue(mockEntryBadges)

    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Owner Access', () => {
    it('should always grant access to entry owner', async () => {
      const testEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.PHI,
      }

      const result = await accessManager.checkAccess(testEntry, mockOwnerContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should grant owner access regardless of privacy level', async () => {
      const privacyLevels = [
        PrivacyLevel.PUBLIC,
        PrivacyLevel.COMMUNITY,
        PrivacyLevel.PRIVATE,
        PrivacyLevel.MEDICAL,
        PrivacyLevel.LEGAL,
        PrivacyLevel.ANONYMOUS,
      ]

      for (const privacyLevel of privacyLevels) {
        const testEntry = {
          ...mockJournalEntry,
          privacyLevel,
        }

        const result = await accessManager.checkAccess(testEntry, mockOwnerContext)
        expect(result.hasAccess).toBe(true)
      }
    })
  })

  describe('Public Access', () => {
    it('should grant access to public entries for any user', async () => {
      const publicEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PUBLIC,
      }

      const result = await accessManager.checkAccess(publicEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should grant public access even with minimal permissions', async () => {
      const minimalContext = {
        ...mockSecurityContext,
        permissions: [],
        authLevel: 'basic' as const,
      }

      const publicEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PUBLIC,
      }

      const result = await accessManager.checkAccess(publicEntry, minimalContext)

      expect(result.hasAccess).toBe(true)
    })
  })

  describe('Community Access', () => {
    it('should grant access to users with matching verified badges', async () => {
      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      const result = await accessManager.checkAccess(communityEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
      expect(accessManager['getUserBadges']).toHaveBeenCalledWith(mockSecurityContext.userDid)
      expect(accessManager['getEntryRelatedBadges']).toHaveBeenCalledWith(communityEntry)
    })

    it('should deny access to users without matching verified badges', async () => {
      // Mock user with no verified badges matching the entry
      jest.spyOn(accessManager as any, 'getUserBadges').mockResolvedValue([
        { type: 'whistleblower', verified: true },
        { type: 'retaliation', verified: false },
      ])

      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      const result = await accessManager.checkAccess(communityEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Requires verified community badge')
    })

    it('should deny access to users with unverified matching badges', async () => {
      // Mock user with matching but unverified badge
      jest.spyOn(accessManager as any, 'getUserBadges').mockResolvedValue([
        { type: 'havana', verified: false },
      ])

      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      const result = await accessManager.checkAccess(communityEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Requires verified community badge')
    })
  })

  describe('Private Access', () => {
    it('should grant access to users in access control list', async () => {
      const privateEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PRIVATE,
        accessControlList: [mockSecurityContext.userDid, 'did:example:charlie'],
      }

      const result = await accessManager.checkAccess(privateEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should deny access to users not in access control list', async () => {
      const privateEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PRIVATE,
        accessControlList: ['did:example:charlie', 'did:example:dave'],
      }

      const result = await accessManager.checkAccess(privateEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Private entry - access not granted')
    })

    it('should deny access when no access control list exists', async () => {
      const privateEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PRIVATE,
      }

      const result = await accessManager.checkAccess(privateEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Private entry - access not granted')
    })
  })

  describe('Medical Access', () => {
    it('should grant access to users with proper permissions and MFA', async () => {
      const medicalContext = {
        ...mockSecurityContext,
        authLevel: 'mfa' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, medicalContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should deny access to users with insufficient permissions', async () => {
      const insufficientContext = {
        ...mockSecurityContext,
        authLevel: 'mfa' as const,
        permissions: ['basic:read'],
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, insufficientContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Insufficient permissions for medical data')
      expect(result.requiredPermissions).toEqual(['medical:read', 'phi:access'])
    })

    it('should deny access to users with basic authentication level', async () => {
      const basicAuthContext = {
        ...mockSecurityContext,
        authLevel: 'basic' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, basicAuthContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Medical data requires MFA or biometric authentication')
    })

    it('should grant access with biometric authentication', async () => {
      const biometricContext = {
        ...mockSecurityContext,
        authLevel: 'biometric' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, biometricContext)

      expect(result.hasAccess).toBe(true)
    })

    it('should require all medical permissions', async () => {
      const partialPermissionContext = {
        ...mockSecurityContext,
        authLevel: 'mfa' as const,
        permissions: ['medical:read'], // Missing 'phi:access'
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, partialPermissionContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Insufficient permissions for medical data')
    })
  })

  describe('Legal Access', () => {
    it('should grant access to users with legal evidence permissions', async () => {
      const legalContext = {
        ...mockSecurityContext,
        permissions: ['legal:evidence:access'],
      }

      const legalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.LEGAL,
      }

      const result = await accessManager.checkAccess(legalEntry, legalContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should deny access to users without legal evidence permissions', async () => {
      const noLegalContext = {
        ...mockSecurityContext,
        permissions: ['basic:read', 'medical:read'],
      }

      const legalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.LEGAL,
      }

      const result = await accessManager.checkAccess(legalEntry, noLegalContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Legal evidence access requires special authorization')
    })
  })

  describe('Anonymous Access', () => {
    it('should grant access to anonymous entries for any user', async () => {
      const anonymousEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.ANONYMOUS,
      }

      const result = await accessManager.checkAccess(anonymousEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(true)
      expect(result.reason).toBeUndefined()
    })

    it('should grant anonymous access even with no permissions', async () => {
      const noPermissionContext = {
        ...mockSecurityContext,
        permissions: [],
      }

      const anonymousEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.ANONYMOUS,
      }

      const result = await accessManager.checkAccess(anonymousEntry, noPermissionContext)

      expect(result.hasAccess).toBe(true)
    })
  })

  describe('Unknown Privacy Level', () => {
    it('should deny access for unknown privacy levels', async () => {
      const unknownEntry = {
        ...mockJournalEntry,
        privacyLevel: 'unknown' as any,
      }

      const result = await accessManager.checkAccess(unknownEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Unknown privacy level')
    })
  })

  describe('Complex Access Scenarios', () => {
    it('should handle entries with multiple privacy requirements', async () => {
      // Medical entry that also requires community access
      const complexEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        accessControlList: [mockSecurityContext.userDid],
      }

      const qualifiedContext = {
        ...mockSecurityContext,
        authLevel: 'mfa' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const result = await accessManager.checkAccess(complexEntry, qualifiedContext)

      expect(result.hasAccess).toBe(true)
    })

    it('should handle cascade of access control checks', async () => {
      // Test that owner access bypasses all other checks
      const restrictedEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.LEGAL,
        classification: SecurityClassification.LEGAL_EVIDENCE,
      }

      const ownerResult = await accessManager.checkAccess(restrictedEntry, mockOwnerContext)
      expect(ownerResult.hasAccess).toBe(true)

      const nonOwnerResult = await accessManager.checkAccess(restrictedEntry, mockSecurityContext)
      expect(nonOwnerResult.hasAccess).toBe(false)
    })
  })

  describe('Badge System Integration', () => {
    it('should handle empty badge lists gracefully', async () => {
      jest.spyOn(accessManager as any, 'getUserBadges').mockResolvedValue([])
      jest.spyOn(accessManager as any, 'getEntryRelatedBadges').mockResolvedValue([])

      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      const result = await accessManager.checkAccess(communityEntry, mockSecurityContext)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Requires verified community badge')
    })

    it('should handle badge service errors gracefully', async () => {
      jest.spyOn(accessManager as any, 'getUserBadges').mockRejectedValue(new Error('Badge service unavailable'))

      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      // Should not throw, but should deny access
      await expect(accessManager.checkAccess(communityEntry, mockSecurityContext))
        .resolves.toEqual({
          hasAccess: false,
          reason: 'Requires verified community badge',
        })
    })

    it('should handle malformed badge data', async () => {
      jest.spyOn(accessManager as any, 'getUserBadges').mockResolvedValue([
        null,
        { type: 'havana' }, // Missing verified field
        { verified: true }, // Missing type field
        { type: 'gangstalked', verified: true }, // Valid badge
      ])

      const communityEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.COMMUNITY,
      }

      const result = await accessManager.checkAccess(communityEntry, mockSecurityContext)

      // Should still work with the one valid badge
      expect(result.hasAccess).toBe(false) // No matching entry badges
    })
  })

  describe('Performance and Edge Cases', () => {
    it('should handle large access control lists efficiently', async () => {
      const largeACL = Array.from({ length: 1000 }, (_, i) => `did:example:user${i}`)
      largeACL.push(mockSecurityContext.userDid) // Add current user

      const privateEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.PRIVATE,
        accessControlList: largeACL,
      }

      const startTime = Date.now()
      const result = await accessManager.checkAccess(privateEntry, mockSecurityContext)
      const endTime = Date.now()

      expect(result.hasAccess).toBe(true)
      expect(endTime - startTime).toBeLessThan(100) // Should be fast
    })

    it('should handle concurrent access checks', async () => {
      const entries = Array.from({ length: 10 }, (_, i) => ({
        ...mockJournalEntry,
        uri: `${mockJournalEntry.uri}-${i}`,
        privacyLevel: i % 2 === 0 ? PrivacyLevel.PUBLIC : PrivacyLevel.COMMUNITY,
      }))

      const results = await Promise.all(
        entries.map(entry => accessManager.checkAccess(entry, mockSecurityContext))
      )

      expect(results).toHaveLength(10)
      results.forEach((result, index) => {
        if (index % 2 === 0) {
          expect(result.hasAccess).toBe(true) // Public entries
        } else {
          expect(result.hasAccess).toBe(true) // Community entries with verified badge
        }
      })
    })

    it('should handle invalid context gracefully', async () => {
      const invalidContext = {} as SecurityContext

      const result = await accessManager.checkAccess(mockJournalEntry, invalidContext)

      // Should handle gracefully without throwing
      expect(result).toBeDefined()
      expect(result.hasAccess).toBeDefined()
    })

    it('should handle incomplete journal entries', async () => {
      const incompleteEntry = {
        uri: 'test-uri',
        author: { did: 'did:example:alice' },
      } as SecureJournalEntry

      const result = await accessManager.checkAccess(incompleteEntry, mockSecurityContext)

      // Should handle gracefully
      expect(result).toBeDefined()
      expect(result.hasAccess).toBeDefined()
    })
  })

  describe('Security Context Validation', () => {
    it('should handle missing userDid in security context', async () => {
      const invalidContext = {
        ...mockSecurityContext,
        userDid: '',
      }

      const result = await accessManager.checkAccess(mockJournalEntry, invalidContext)

      expect(result.hasAccess).toBe(true) // Public entry
    })

    it('should handle missing permissions array', async () => {
      const contextWithoutPermissions = {
        ...mockSecurityContext,
        permissions: undefined as any,
      }

      const medicalEntry = {
        ...mockJournalEntry,
        privacyLevel: PrivacyLevel.MEDICAL,
      }

      const result = await accessManager.checkAccess(medicalEntry, contextWithoutPermissions)

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('Insufficient permissions for medical data')
    })

    it('should handle different authentication levels', async () => {
      const authLevels = ['basic', 'mfa', 'biometric'] as const

      for (const authLevel of authLevels) {
        const context = {
          ...mockSecurityContext,
          authLevel,
          permissions: ['medical:read', 'phi:access'],
        }

        const medicalEntry = {
          ...mockJournalEntry,
          privacyLevel: PrivacyLevel.MEDICAL,
        }

        const result = await accessManager.checkAccess(medicalEntry, context)

        if (authLevel === 'basic') {
          expect(result.hasAccess).toBe(false)
        } else {
          expect(result.hasAccess).toBe(true)
        }
      }
    })
  })
})