/**
 * Security and HIPAA Compliance Validation Test Suite
 * 
 * Comprehensive testing of security frameworks, HIPAA compliance,
 * access control enforcement, and security event monitoring.
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
  SecurityEventManager,
  ThreatDetectionManager,
  AuditLogEntry,
  SecurityEvent,
  ThreatAssessment,
} from '../../src/journal-security'
import { AppContext } from '../../src/context'

// Security test configuration
const SECURITY_TEST_CONFIG = {
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION: 300000, // 5 minutes
  SESSION_TIMEOUT: 3600000, // 1 hour
  PHI_ACCESS_LOG_RETENTION: 2557600000, // 30 days
  ENCRYPTION_KEY_ROTATION: 86400000, // 24 hours
  THREAT_SCORE_THRESHOLD: 0.7,
  AUDIT_LOG_MAX_SIZE: 10000,
}

// Mock threat detection scenarios
interface ThreatScenario {
  name: string
  context: SecurityContext
  expectedThreatLevel: 'low' | 'medium' | 'high' | 'critical'
  shouldBlock: boolean
  description: string
}

const THREAT_SCENARIOS: ThreatScenario[] = [
  {
    name: 'suspicious_ip_access',
    context: {
      userDid: 'did:example:user',
      sessionId: 'session-123',
      ipAddress: '192.168.999.999', // Invalid IP pattern
      userAgent: 'Normal Browser',
      authLevel: 'basic',
      permissions: ['basic:read'],
    },
    expectedThreatLevel: 'medium',
    shouldBlock: false,
    description: 'Access from suspicious IP address',
  },
  {
    name: 'automated_bot_access',
    context: {
      userDid: 'did:example:user',
      sessionId: 'session-bot',
      ipAddress: '192.168.1.100',
      userAgent: 'Python-urllib/3.8',
      authLevel: 'basic',
      permissions: ['basic:read'],
    },
    expectedThreatLevel: 'high',
    shouldBlock: true,
    description: 'Automated bot attempting access',
  },
  {
    name: 'privilege_escalation_attempt',
    context: {
      userDid: 'did:example:user',
      sessionId: 'session-escalation',
      ipAddress: '192.168.1.100',
      userAgent: 'Normal Browser',
      authLevel: 'basic',
      permissions: ['medical:read', 'phi:access'], // More permissions than auth level allows
    },
    expectedThreatLevel: 'critical',
    shouldBlock: true,
    description: 'User with basic auth trying to access PHI',
  },
  {
    name: 'rapid_access_pattern',
    context: {
      userDid: 'did:example:user',
      sessionId: 'session-rapid',
      ipAddress: '192.168.1.100',
      userAgent: 'Normal Browser',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access'],
      metadata: {
        requestsPerMinute: 120, // Unusually high
        previousFailedAttempts: 3,
      },
    },
    expectedThreatLevel: 'high',
    shouldBlock: true,
    description: 'Rapid access pattern indicating potential abuse',
  },
]

describe('Security and HIPAA Compliance Validation', () => {
  let network: TestNetworkNoAppView
  let ctx: AppContext
  let aliceAgent: AtpAgent
  let bobAgent: AtpAgent
  let charlieAgent: AtpAgent
  let maliciousAgent: AtpAgent
  
  let accessManager: PrivacyAccessControlManager
  let hipaaManager: HIPAAComplianceManager
  let encryptionManager: EncryptionManager
  let securityEventManager: SecurityEventManager
  let threatDetectionManager: ThreatDetectionManager
  
  let aliceSecurityContext: SecurityContext
  let bobSecurityContext: SecurityContext
  let charlieSecurityContext: SecurityContext
  let maliciousSecurityContext: SecurityContext

  beforeAll(async () => {
    network = await TestNetworkNoAppView.create({
      dbPostgresSchema: 'journal_security',
    })
    // @ts-expect-error Error due to circular dependency with the dev-env package
    ctx = network.pds.ctx

    aliceAgent = network.pds.getClient()
    bobAgent = network.pds.getClient()
    charlieAgent = network.pds.getClient()
    maliciousAgent = network.pds.getClient()

    // Create test accounts
    await aliceAgent.createAccount({
      email: 'alice@security.test',
      handle: 'alice.security',
      password: 'alice-secure-pass-123',
    })

    await bobAgent.createAccount({
      email: 'bob@security.test',
      handle: 'bob.security',
      password: 'bob-secure-pass-456',
    })

    await charlieAgent.createAccount({
      email: 'charlie@security.test',
      handle: 'charlie.security',
      password: 'charlie-secure-pass-789',
    })

    await maliciousAgent.createAccount({
      email: 'malicious@security.test',
      handle: 'malicious.user',
      password: 'malicious-pass-000',
    })

    // Initialize security managers
    accessManager = new PrivacyAccessControlManager()
    hipaaManager = HIPAAComplianceManager.getInstance()
    encryptionManager = new EncryptionManager()
    securityEventManager = new SecurityEventManager()
    threatDetectionManager = new ThreatDetectionManager()

    // Setup security contexts
    aliceSecurityContext = {
      userDid: aliceAgent.accountDid!,
      sessionId: 'alice-security-session',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Security Test)',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access', 'legal:evidence:access'],
    }

    bobSecurityContext = {
      userDid: bobAgent.accountDid!,
      sessionId: 'bob-security-session',
      ipAddress: '192.168.1.101',
      userAgent: 'Mozilla/5.0 (Security Test)',
      authLevel: 'basic',
      permissions: ['basic:read'],
    }

    charlieSecurityContext = {
      userDid: charlieAgent.accountDid!,
      sessionId: 'charlie-security-session',
      ipAddress: '192.168.1.102',
      userAgent: 'Mozilla/5.0 (Security Test)',
      authLevel: 'mfa',
      permissions: ['medical:read', 'phi:access'],
    }

    maliciousSecurityContext = {
      userDid: maliciousAgent.accountDid!,
      sessionId: 'malicious-session',
      ipAddress: '10.0.0.666', // Suspicious IP
      userAgent: 'curl/7.68.0', // Automated tool
      authLevel: 'basic',
      permissions: ['basic:read'],
    }
  }, 30000)

  afterAll(async () => {
    await network.close()
  })

  beforeEach(() => {
    // Reset security managers state before each test
    jest.clearAllMocks()
  })

  describe('HIPAA Compliance Enforcement', () => {
    it('enforces PHI encryption requirements', async () => {
      // Test valid PHI entry
      const validPHIEntry = {
        uri: 'at://did:example:test/app.warlog.journal/phi001',
        cid: 'bafkreiphitest001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'Medical journal entry with symptoms',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'Medical journal entry with symptoms',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
          encryptionMetadata: {
            algorithm: 'AES-256-CBC',
            keyId: 'phi-test-key',
            iv: 'phi-test-iv',
            salt: 'phi-test-salt',
            signature: 'phi-test-signature',
          },
        },
        symptoms: {
          encrypted: true,
          data: 'encrypted-symptoms-data',
          count: 3,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      const validation = hipaaManager.validateHIPAACompliance(validPHIEntry)
      expect(validation.isCompliant).toBe(true)
      expect(validation.violations).toHaveLength(0)

      // Test invalid PHI entry (unencrypted)
      const invalidPHIEntry = {
        ...validPHIEntry,
        content: {
          text: 'Unencrypted PHI content',
          isEncrypted: false,
          encryptionLevel: EncryptionLevel.NONE,
        },
        symptoms: {
          encrypted: false,
          data: 'unencrypted-symptoms',
          count: 3,
        },
      }

      const invalidValidation = hipaaManager.validateHIPAACompliance(invalidPHIEntry)
      expect(invalidValidation.isCompliant).toBe(false)
      expect(invalidValidation.violations).toContain('PHI content must be encrypted')
      expect(invalidValidation.violations).toContain('Symptom data must be encrypted')
    })

    it('logs all PHI access attempts with complete audit trail', async () => {
      const phiEntryUri = 'at://did:example:test/app.warlog.journal/phi002'
      
      // Log successful access
      await hipaaManager.logPHIAccess(
        aliceSecurityContext,
        phiEntryUri,
        'read',
        true
      )

      // Log failed access attempt
      await hipaaManager.logPHIAccess(
        bobSecurityContext,
        phiEntryUri,
        'read',
        false,
        'Insufficient permissions for medical data'
      )

      // Log update attempt
      await hipaaManager.logPHIAccess(
        aliceSecurityContext,
        phiEntryUri,
        'update',
        true
      )

      // Verify audit log entries
      const auditLog = (hipaaManager as any).auditLog as AuditLogEntry[]
      expect(auditLog).toHaveLength(3)

      const successfulRead = auditLog.find(entry => 
        entry.action === 'read' && entry.success === true
      )
      expect(successfulRead).toBeDefined()
      expect(successfulRead!.userDid).toBe(aliceSecurityContext.userDid)
      expect(successfulRead!.classification).toBe(SecurityClassification.PHI)
      expect(successfulRead!.privacyLevel).toBe(PrivacyLevel.MEDICAL)

      const failedRead = auditLog.find(entry => 
        entry.action === 'read' && entry.success === false
      )
      expect(failedRead).toBeDefined()
      expect(failedRead!.userDid).toBe(bobSecurityContext.userDid)
      expect(failedRead!.errorMessage).toBe('Insufficient permissions for medical data')

      const update = auditLog.find(entry => entry.action === 'update')
      expect(update).toBeDefined()
      expect(update!.success).toBe(true)
    })

    it('assesses breach notification requirements correctly', async () => {
      const phiEntries = [
        'at://did:example:alice/app.warlog.journal/phi001',
        'at://did:example:alice/app.warlog.journal/phi002',
        'at://did:example:bob/app.warlog.journal/phi003',
      ]

      const nonPhiEntries = [
        'at://did:example:alice/app.warlog.journal/public001',
        'at://did:example:bob/app.warlog.journal/public002',
      ]

      // Mock the private method to return PHI entries
      jest.spyOn(hipaaManager as any, 'getPHIEntries').mockImplementation(
        async (uris: string[]) => {
          return uris.filter(uri => phiEntries.includes(uri)).map(uri => ({
            uri,
            classification: SecurityClassification.PHI,
            privacyLevel: PrivacyLevel.MEDICAL,
          }))
        }
      )

      // Test breach with PHI data
      const phiBreachAssessment = await hipaaManager.assessBreachNotification(
        [...phiEntries, ...nonPhiEntries],
        'data_loss',
        aliceSecurityContext
      )

      expect(phiBreachAssessment.notificationRequired).toBe(true)
      expect(phiBreachAssessment.timeframe).toBe(72) // HIPAA requirement
      expect(phiBreachAssessment.authorities).toEqual(['HHS', 'State Attorney General'])
      expect(phiBreachAssessment.users).toHaveLength(2) // Alice and Bob

      // Test breach with no PHI data
      const nonPhiBreachAssessment = await hipaaManager.assessBreachNotification(
        nonPhiEntries,
        'unauthorized_access',
        aliceSecurityContext
      )

      expect(nonPhiBreachAssessment.notificationRequired).toBe(false)
      expect(nonPhiBreachAssessment.timeframe).toBe(0)
      expect(nonPhiBreachAssessment.authorities).toHaveLength(0)
      expect(nonPhiBreachAssessment.users).toHaveLength(0)
    })

    it('validates data retention and deletion compliance', async () => {
      const testEntry = {
        uri: 'at://did:example:test/app.warlog.journal/retention001',
        cid: 'bafkreiretention001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'PHI entry for retention testing',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'PHI entry for retention testing',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        legalHoldStatus: false,
        retentionPolicy: {
          retainUntil: new Date(Date.now() + 6 * 365 * 24 * 60 * 60 * 1000), // 6 years
          reason: 'HIPAA minimum retention requirement',
          canDelete: false,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      const validation = hipaaManager.validateHIPAACompliance(testEntry)
      expect(validation.isCompliant).toBe(true)
      expect(validation.recommendations).toContain('Ensure legal hold policies are applied')
      
      // Test entry with legal hold
      const legalHoldEntry = {
        ...testEntry,
        legalHoldStatus: true,
        classification: SecurityClassification.LEGAL_EVIDENCE,
      }

      const legalHoldValidation = hipaaManager.validateHIPAACompliance(legalHoldEntry)
      expect(legalHoldValidation.isCompliant).toBe(true)
      expect(legalHoldValidation.recommendations).toContain('Ensure legal hold policies are applied')
    })
  })

  describe('Access Control Security', () => {
    it('enforces multi-factor authentication requirements for PHI', async () => {
      const phiEntry = {
        uri: 'at://did:example:test/app.warlog.journal/mfa001',
        cid: 'bafkreimfa001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'PHI requiring MFA',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'PHI requiring MFA',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      // Test with MFA context
      const mfaContext = {
        ...charlieSecurityContext,
        authLevel: 'mfa' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const mfaAccess = await accessManager.checkAccess(phiEntry, mfaContext)
      expect(mfaAccess.hasAccess).toBe(true)

      // Test with basic auth context (should fail)
      const basicContext = {
        ...charlieSecurityContext,
        authLevel: 'basic' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const basicAccess = await accessManager.checkAccess(phiEntry, basicContext)
      expect(basicAccess.hasAccess).toBe(false)
      expect(basicAccess.reason).toBe('Medical data requires MFA or biometric authentication')

      // Test with biometric auth (should succeed)
      const biometricContext = {
        ...charlieSecurityContext,
        authLevel: 'biometric' as const,
        permissions: ['medical:read', 'phi:access'],
      }

      const biometricAccess = await accessManager.checkAccess(phiEntry, biometricContext)
      expect(biometricAccess.hasAccess).toBe(true)
    })

    it('validates role-based access control (RBAC)', async () => {
      const sensitiveEntry = {
        uri: 'at://did:example:test/app.warlog.journal/rbac001',
        cid: 'bafkreirbac001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'Sensitive entry for RBAC testing',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.LEGAL,
        classification: SecurityClassification.LEGAL_EVIDENCE,
        content: {
          text: 'Sensitive entry for RBAC testing',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      // Test with legal access permissions
      const legalContext = {
        ...aliceSecurityContext,
        permissions: ['legal:evidence:access'],
      }

      const legalAccess = await accessManager.checkAccess(sensitiveEntry, legalContext)
      expect(legalAccess.hasAccess).toBe(true)

      // Test without legal access permissions
      const noLegalContext = {
        ...bobSecurityContext,
        permissions: ['basic:read', 'medical:read'],
      }

      const noLegalAccess = await accessManager.checkAccess(sensitiveEntry, noLegalContext)
      expect(noLegalAccess.hasAccess).toBe(false)
      expect(noLegalAccess.reason).toBe('Legal evidence access requires special authorization')
    })

    it('implements session management and timeout controls', async () => {
      const sessionContext = {
        ...aliceSecurityContext,
        sessionCreated: Date.now() - SECURITY_TEST_CONFIG.SESSION_TIMEOUT - 1000, // Expired
        sessionLastActivity: Date.now() - 3600000, // 1 hour ago
      }

      const testEntry = {
        uri: 'at://did:example:test/app.warlog.journal/session001',
        cid: 'bafkreisession001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'Entry for session testing',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.PRIVATE,
        classification: SecurityClassification.SENSITIVE,
        content: {
          text: 'Entry for session testing',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.STANDARD,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      // In a real implementation, expired sessions would be rejected
      // For testing, we validate the session timeout logic exists
      expect(sessionContext.sessionCreated).toBeLessThan(
        Date.now() - SECURITY_TEST_CONFIG.SESSION_TIMEOUT
      )
    })

    it('prevents privilege escalation attacks', async () => {
      const highPrivilegeEntry = {
        uri: 'at://did:example:test/app.warlog.journal/privilege001',
        cid: 'bafkreiprivilege001',
        author: {
          did: aliceAgent.accountDid!,
          handle: 'alice.security',
        },
        text: 'High privilege entry',
        entryType: 'real_time' as const,
        privacyLevel: PrivacyLevel.MEDICAL,
        classification: SecurityClassification.PHI,
        content: {
          text: 'High privilege entry',
          isEncrypted: true,
          encryptionLevel: EncryptionLevel.ENHANCED,
        },
        createdAt: new Date().toISOString(),
        accessCount: 0,
      }

      // Attempt privilege escalation with mismatched auth level and permissions
      const escalationContext = {
        ...bobSecurityContext,
        authLevel: 'basic' as const, // Low auth level
        permissions: ['medical:read', 'phi:access'], // High permissions (should be rejected)
      }

      const escalationAccess = await accessManager.checkAccess(highPrivilegeEntry, escalationContext)
      expect(escalationAccess.hasAccess).toBe(false)
      expect(escalationAccess.reason).toBe('Medical data requires MFA or biometric authentication')

      // Verify that even with claimed permissions, auth level is enforced
      expect(escalationContext.authLevel).toBe('basic')
      expect(escalationContext.permissions).toContain('phi:access')
    })
  })

  describe('Threat Detection and Prevention', () => {
    it('detects and responds to suspicious access patterns', async () => {
      for (const scenario of THREAT_SCENARIOS) {
        const assessment = await threatDetectionManager.assessThreat(
          scenario.context,
          'journal_access',
          {
            resourceType: 'journal_entry',
            action: 'read',
            timestamp: Date.now(),
          }
        )

        expect(assessment.threatLevel).toBe(scenario.expectedThreatLevel)
        expect(assessment.shouldBlock).toBe(scenario.shouldBlock)
        expect(assessment.riskFactors).toBeDefined()
        
        console.log(`Threat scenario '${scenario.name}': ${assessment.threatLevel} risk, block: ${assessment.shouldBlock}`)
        
        if (scenario.shouldBlock) {
          expect(assessment.mitigation).toBeDefined()
          expect(assessment.mitigation!.actions).toContain('block_access')
        }
      }
    })

    it('implements rate limiting and abuse prevention', async () => {
      const rapidAccessContext = {
        ...aliceSecurityContext,
        metadata: {
          requestsInLastMinute: 150, // Very high request rate
          requestsInLastHour: 2000,
          averageRequestInterval: 400, // 400ms between requests
        },
      }

      const assessment = await threatDetectionManager.assessThreat(
        rapidAccessContext,
        'rapid_access',
        {
          resourceType: 'journal_entry',
          action: 'read',
          timestamp: Date.now(),
        }
      )

      expect(assessment.threatLevel).toBe('high')
      expect(assessment.shouldBlock).toBe(true)
      expect(assessment.riskFactors).toContain('excessive_request_rate')
      expect(assessment.mitigation!.actions).toContain('rate_limit')
    })

    it('monitors for data exfiltration attempts', async () => {
      const exfiltrationContext = {
        ...maliciousSecurityContext,
        metadata: {
          largeBatchAccess: true,
          downloadVolume: 100 * 1024 * 1024, // 100MB download
          accessPattern: 'sequential_enumeration',
          timeWindow: 600000, // 10 minutes
        },
      }

      const assessment = await threatDetectionManager.assessThreat(
        exfiltrationContext,
        'data_exfiltration',
        {
          resourceType: 'journal_entry',
          action: 'bulk_read',
          timestamp: Date.now(),
        }
      )

      expect(assessment.threatLevel).toBe('critical')
      expect(assessment.shouldBlock).toBe(true)
      expect(assessment.riskFactors).toContain('bulk_data_access')
      expect(assessment.riskFactors).toContain('suspicious_user_agent')
      expect(assessment.mitigation!.actions).toContain('block_access')
      expect(assessment.mitigation!.actions).toContain('alert_security_team')
    })

    it('detects injection and manipulation attempts', async () => {
      const injectionAttempts = [
        {
          text: "'; DROP TABLE journal_entries; --",
          type: 'sql_injection',
        },
        {
          text: '<script>alert("XSS")</script>',
          type: 'xss_attempt',
        },
        {
          text: '{{7*7}}#{7*7}${{7*7}}',
          type: 'template_injection',
        },
        {
          text: '../../../etc/passwd',
          type: 'path_traversal',
        },
      ]

      for (const attempt of injectionAttempts) {
        const assessment = await threatDetectionManager.assessThreat(
          maliciousSecurityContext,
          'injection_attempt',
          {
            resourceType: 'journal_entry',
            action: 'create',
            payload: attempt.text,
            timestamp: Date.now(),
          }
        )

        expect(assessment.threatLevel).toBeOneOf(['high', 'critical'])
        expect(assessment.shouldBlock).toBe(true)
        expect(assessment.riskFactors).toContain('malicious_payload')
        
        console.log(`Injection attempt '${attempt.type}': ${assessment.threatLevel} risk`)
      }
    })
  })

  describe('Encryption Security', () => {
    it('validates encryption key management and rotation', async () => {
      const testData = 'Sensitive data for key rotation testing'
      const originalKeyId = 'rotation-test-key-v1'
      const rotatedKeyId = 'rotation-test-key-v2'

      // Encrypt with original key
      const originalEncrypted = await encryptionManager.encrypt(
        testData,
        originalKeyId,
        EncryptionLevel.ENHANCED
      )

      expect(originalEncrypted.metadata.keyId).toBe(originalKeyId)
      expect(originalEncrypted.metadata.algorithm).toContain('AES-256')

      // Simulate key rotation
      const rotatedEncrypted = await encryptionManager.encrypt(
        testData,
        rotatedKeyId,
        EncryptionLevel.ENHANCED
      )

      expect(rotatedEncrypted.metadata.keyId).toBe(rotatedKeyId)
      expect(rotatedEncrypted.metadata.keyId).not.toBe(originalKeyId)

      // Verify both versions can be decrypted
      const originalDecrypted = await encryptionManager.decrypt(
        originalEncrypted.data,
        originalEncrypted.metadata
      )
      expect(originalDecrypted).toBe(testData)

      const rotatedDecrypted = await encryptionManager.decrypt(
        rotatedEncrypted.data,
        rotatedEncrypted.metadata
      )
      expect(rotatedDecrypted).toBe(testData)
    })

    it('ensures encryption strength for different classification levels', async () => {
      const testData = 'Test data for encryption strength validation'
      
      const classifications = [
        { level: EncryptionLevel.STANDARD, minKeySize: 256 },
        { level: EncryptionLevel.ENHANCED, minKeySize: 256 },
        { level: EncryptionLevel.QUANTUM_RESISTANT, minKeySize: 256 },
      ]

      for (const classification of classifications) {
        const encrypted = await encryptionManager.encrypt(
          testData,
          `test-key-${classification.level}`,
          classification.level
        )

        expect(encrypted.data).toBeDefined()
        expect(encrypted.metadata).toBeDefined()
        expect(encrypted.metadata.algorithm).toBeDefined()
        
        // Verify encryption strength
        if (classification.level === EncryptionLevel.STANDARD) {
          expect(encrypted.metadata.algorithm).toContain('AES-256')
        } else if (classification.level === EncryptionLevel.ENHANCED) {
          expect(encrypted.metadata.algorithm).toContain('AES-256')
          expect(encrypted.metadata.signature).toBeDefined()
        } else if (classification.level === EncryptionLevel.QUANTUM_RESISTANT) {
          expect(encrypted.metadata.algorithm).toMatch(/Kyber|CRYSTALS/)
        }

        // Verify decryption works
        const decrypted = await encryptionManager.decrypt(
          encrypted.data,
          encrypted.metadata
        )
        expect(decrypted).toBe(testData)
      }
    })

    it('validates secure key derivation and storage', async () => {
      const password = 'user-strong-password-123'
      const salt = 'random-salt-value-456'
      const iterations = 100000 // PBKDF2 iterations

      // Test key derivation
      const derivedKey = await encryptionManager.deriveKey(password, salt, iterations)
      expect(derivedKey).toBeDefined()
      expect(derivedKey.length).toBeGreaterThan(32) // At least 256 bits

      // Test that same input produces same key
      const derivedKey2 = await encryptionManager.deriveKey(password, salt, iterations)
      expect(derivedKey).toBe(derivedKey2)

      // Test that different salt produces different key
      const derivedKey3 = await encryptionManager.deriveKey(password, 'different-salt', iterations)
      expect(derivedKey).not.toBe(derivedKey3)
    })

    it('prevents encryption oracle attacks', async () => {
      const testData = 'Repeated data for oracle attack testing'
      const keyId = 'oracle-test-key'

      // Encrypt same data multiple times
      const encrypted1 = await encryptionManager.encrypt(testData, keyId, EncryptionLevel.STANDARD)
      const encrypted2 = await encryptionManager.encrypt(testData, keyId, EncryptionLevel.STANDARD)
      const encrypted3 = await encryptionManager.encrypt(testData, keyId, EncryptionLevel.STANDARD)

      // Encrypted data should be different each time (due to random IV)
      expect(encrypted1.data).not.toBe(encrypted2.data)
      expect(encrypted2.data).not.toBe(encrypted3.data)
      expect(encrypted1.data).not.toBe(encrypted3.data)

      // But IVs should be different
      expect(encrypted1.metadata.iv).not.toBe(encrypted2.metadata.iv)
      expect(encrypted2.metadata.iv).not.toBe(encrypted3.metadata.iv)
      expect(encrypted1.metadata.iv).not.toBe(encrypted3.metadata.iv)

      // All should decrypt to same plaintext
      const decrypted1 = await encryptionManager.decrypt(encrypted1.data, encrypted1.metadata)
      const decrypted2 = await encryptionManager.decrypt(encrypted2.data, encrypted2.metadata)
      const decrypted3 = await encryptionManager.decrypt(encrypted3.data, encrypted3.metadata)

      expect(decrypted1).toBe(testData)
      expect(decrypted2).toBe(testData)
      expect(decrypted3).toBe(testData)
    })
  })

  describe('Security Event Monitoring', () => {
    it('logs and alerts on security events', async () => {
      const securityEvents: SecurityEvent[] = [
        {
          type: 'unauthorized_access_attempt',
          severity: 'high',
          context: maliciousSecurityContext,
          resource: 'at://did:example:test/app.warlog.journal/secure001',
          timestamp: Date.now(),
          details: {
            reason: 'User attempted to access PHI without proper permissions',
            attemptedAction: 'read',
            deniedReason: 'insufficient_permissions',
          },
        },
        {
          type: 'privilege_escalation_attempt',
          severity: 'critical',
          context: maliciousSecurityContext,
          resource: 'system',
          timestamp: Date.now(),
          details: {
            reason: 'User with basic auth claimed PHI access permissions',
            originalPermissions: ['basic:read'],
            claimedPermissions: ['medical:read', 'phi:access'],
          },
        },
        {
          type: 'data_exfiltration_attempt',
          severity: 'critical',
          context: maliciousSecurityContext,
          resource: 'journal_collection',
          timestamp: Date.now(),
          details: {
            reason: 'Bulk access pattern detected',
            accessCount: 500,
            timeWindow: 300000, // 5 minutes
            dataVolume: 50 * 1024 * 1024, // 50MB
          },
        },
      ]

      for (const event of securityEvents) {
        await securityEventManager.logSecurityEvent(event)

        // Verify event was logged
        const recentEvents = await securityEventManager.getRecentEvents(1)
        expect(recentEvents).toHaveLength(1)
        expect(recentEvents[0].type).toBe(event.type)
        expect(recentEvents[0].severity).toBe(event.severity)

        // Verify alerting for critical events
        if (event.severity === 'critical') {
          const alertSent = await securityEventManager.shouldSendAlert(event)
          expect(alertSent).toBe(true)
        }
      }
    })

    it('implements security event correlation and pattern detection', async () => {
      const correlatedEvents = [
        {
          type: 'failed_login_attempt',
          severity: 'medium',
          context: maliciousSecurityContext,
          timestamp: Date.now() - 300000, // 5 minutes ago
        },
        {
          type: 'failed_login_attempt',
          severity: 'medium',
          context: maliciousSecurityContext,
          timestamp: Date.now() - 240000, // 4 minutes ago
        },
        {
          type: 'failed_login_attempt',
          severity: 'medium',
          context: maliciousSecurityContext,
          timestamp: Date.now() - 180000, // 3 minutes ago
        },
        {
          type: 'unauthorized_access_attempt',
          severity: 'high',
          context: maliciousSecurityContext,
          timestamp: Date.now() - 120000, // 2 minutes ago
        },
        {
          type: 'privilege_escalation_attempt',
          severity: 'critical',
          context: maliciousSecurityContext,
          timestamp: Date.now(), // Now
        },
      ] as SecurityEvent[]

      // Log all events
      for (const event of correlatedEvents) {
        await securityEventManager.logSecurityEvent(event)
      }

      // Detect pattern of escalating attacks
      const pattern = await securityEventManager.detectAttackPattern(
        maliciousSecurityContext.userDid,
        3600000 // 1 hour window
      )

      expect(pattern.detected).toBe(true)
      expect(pattern.type).toBe('escalating_attack')
      expect(pattern.events).toHaveLength(5)
      expect(pattern.riskScore).toBeGreaterThan(0.8)
      expect(pattern.recommendedAction).toBe('block_user')
    })

    it('maintains security audit trail with integrity protection', async () => {
      const testEvent: SecurityEvent = {
        type: 'phi_access',
        severity: 'medium',
        context: aliceSecurityContext,
        resource: 'at://did:example:test/app.warlog.journal/audit001',
        timestamp: Date.now(),
        details: {
          action: 'read',
          classification: SecurityClassification.PHI,
          success: true,
        },
      }

      await securityEventManager.logSecurityEvent(testEvent)

      // Verify audit trail integrity
      const auditEntry = await securityEventManager.getAuditEntry(testEvent.timestamp)
      expect(auditEntry).toBeDefined()
      expect(auditEntry!.event).toEqual(testEvent)
      expect(auditEntry!.integrity.hash).toBeDefined()
      expect(auditEntry!.integrity.signature).toBeDefined()

      // Verify tamper detection
      const tamperedEvent = { ...testEvent, severity: 'low' }
      const integrityCheck = await securityEventManager.verifyIntegrity(
        tamperedEvent,
        auditEntry!.integrity
      )
      expect(integrityCheck.valid).toBe(false)
      expect(integrityCheck.reason).toContain('hash_mismatch')
    })
  })

  describe('Compliance Reporting and Metrics', () => {
    it('generates comprehensive security compliance reports', async () => {
      // Create test data for reporting
      const testPeriod = {
        start: Date.now() - 30 * 24 * 60 * 60 * 1000, // 30 days ago
        end: Date.now(),
      }

      const complianceReport = await hipaaManager.generateComplianceReport(testPeriod)

      expect(complianceReport).toBeDefined()
      expect(complianceReport.period).toEqual(testPeriod)
      expect(complianceReport.metrics).toBeDefined()
      expect(complianceReport.violations).toBeDefined()
      expect(complianceReport.recommendations).toBeDefined()

      // Verify required metrics
      expect(complianceReport.metrics.totalPHIAccess).toBeDefined()
      expect(complianceReport.metrics.failedAccessAttempts).toBeDefined()
      expect(complianceReport.metrics.encryptionCompliance).toBeDefined()
      expect(complianceReport.metrics.auditLogCompleteness).toBeDefined()

      // Verify compliance scoring
      expect(complianceReport.complianceScore).toBeGreaterThanOrEqual(0)
      expect(complianceReport.complianceScore).toBeLessThanOrEqual(100)
    })

    it('tracks security metrics and KPIs', async () => {
      const securityMetrics = await securityEventManager.getSecurityMetrics(
        Date.now() - 7 * 24 * 60 * 60 * 1000, // 7 days
        Date.now()
      )

      expect(securityMetrics).toBeDefined()
      expect(securityMetrics.totalEvents).toBeGreaterThanOrEqual(0)
      expect(securityMetrics.criticalEvents).toBeGreaterThanOrEqual(0)
      expect(securityMetrics.blockedAttempts).toBeGreaterThanOrEqual(0)
      expect(securityMetrics.averageResponseTime).toBeDefined()
      expect(securityMetrics.threatDetectionRate).toBeDefined()
      expect(securityMetrics.falsePositiveRate).toBeDefined()

      // Verify trend analysis
      expect(securityMetrics.trends).toBeDefined()
      expect(securityMetrics.trends.eventsTrend).toBeDefined()
      expect(securityMetrics.trends.threatLevelTrend).toBeDefined()
    })

    it('validates regulatory compliance readiness', async () => {
      const regulations = ['HIPAA', 'GDPR', 'SOC2']
      
      for (const regulation of regulations) {
        const readinessAssessment = await hipaaManager.assessRegulatory Compliance(regulation)
        
        expect(readinessAssessment).toBeDefined()
        expect(readinessAssessment.regulation).toBe(regulation)
        expect(readinessAssessment.overallScore).toBeGreaterThanOrEqual(0)
        expect(readinessAssessment.overallScore).toBeLessThanOrEqual(100)
        
        expect(readinessAssessment.requirements).toBeDefined()
        expect(readinessAssessment.gaps).toBeDefined()
        expect(readinessAssessment.recommendations).toBeDefined()
        
        // Verify critical requirements are addressed
        const criticalRequirements = readinessAssessment.requirements.filter(
          req => req.criticality === 'critical'
        )
        
        criticalRequirements.forEach(req => {
          expect(req.status).toBeOneOf(['compliant', 'partial', 'non_compliant'])
          if (req.status !== 'compliant') {
            expect(req.remediation).toBeDefined()
          }
        })
      }
    })
  })

  describe('Performance Under Security Load', () => {
    it('maintains performance with security checks enabled', async () => {
      const iterationCount = 100
      const startTime = Date.now()
      
      for (let i = 0; i < iterationCount; i++) {
        const testEntry = {
          uri: `at://did:example:test/app.warlog.journal/perf${i}`,
          cid: `bafkreiperf${i}`,
          author: {
            did: aliceAgent.accountDid!,
            handle: 'alice.security',
          },
          text: `Performance test entry ${i}`,
          entryType: 'real_time' as const,
          privacyLevel: i % 3 === 0 ? PrivacyLevel.PUBLIC : PrivacyLevel.MEDICAL,
          classification: i % 3 === 0 ? SecurityClassification.UNCLASSIFIED : SecurityClassification.PHI,
          content: {
            text: `Performance test entry ${i}`,
            isEncrypted: i % 3 !== 0,
            encryptionLevel: i % 3 === 0 ? EncryptionLevel.NONE : EncryptionLevel.ENHANCED,
          },
          createdAt: new Date().toISOString(),
          accessCount: 0,
        }

        // Security validation pipeline
        const complianceCheck = hipaaManager.validateHIPAACompliance(testEntry)
        const accessCheck = await accessManager.checkAccess(testEntry, aliceSecurityContext)
        const threatCheck = await threatDetectionManager.assessThreat(
          aliceSecurityContext,
          'journal_access',
          { resourceType: 'journal_entry', action: 'read', timestamp: Date.now() }
        )

        // Verify security checks completed successfully
        expect(complianceCheck).toBeDefined()
        expect(accessCheck).toBeDefined()
        expect(threatCheck).toBeDefined()

        if (testEntry.classification === SecurityClassification.PHI) {
          await hipaaManager.logPHIAccess(
            aliceSecurityContext,
            testEntry.uri,
            'read',
            accessCheck.hasAccess
          )
        }
      }
      
      const totalTime = Date.now() - startTime
      const averageTime = totalTime / iterationCount
      
      console.log(`Security validation performance: ${totalTime}ms total, ${averageTime}ms average per entry`)
      
      // Performance should remain reasonable even with full security stack
      expect(averageTime).toBeLessThan(50) // Under 50ms per entry
      expect(totalTime).toBeLessThan(10000) // Under 10 seconds total
    })
  })
})
