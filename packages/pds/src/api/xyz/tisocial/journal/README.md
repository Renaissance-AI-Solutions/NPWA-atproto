# TISocial Journal API Integration Guide

This document provides comprehensive integration guidance for the TISocial journal system, including AT Protocol lexicons, XRPC endpoints, and security framework integration.

## Overview

The TISocial journal system implements a secure, privacy-aware journaling platform for targeted individuals with the following key features:

- **HIPAA-compliant** medical data handling
- **Multi-tier privacy controls** (private, contacts, badge community, public, anonymous, medical)
- **Security classifications** (unclassified, sensitive, PHI, legal evidence, whistleblower)
- **End-to-end encryption** for sensitive content
- **Audit logging** for compliance and security monitoring
- **Badge-based community access** control

## Architecture

### Core Components

1. **Security Framework** (`journal-security.ts`)
   - HIPAAComplianceManager
   - PrivacyAccessControlManager  
   - JournalEncryptionManager
   - SecurityEventMonitor

2. **AT Protocol Lexicons**
   - `xyz.tisocial.journal.entry` - Core journal entry schema
   - `xyz.tisocial.journal.feed` - Feed generation and querying
   - `xyz.tisocial.journal.privacy` - Privacy controls and access management
   - `xyz.tisocial.journal.analytics` - Privacy-protected analytics

3. **XRPC Handlers**
   - Entry management (create, read, update, delete)
   - Feed generation with privacy filtering
   - Privacy control management
   - Access request workflows

## Lexicon Schemas

### Enhanced Journal Entry (`xyz.tisocial.journal.entry`)

```typescript
interface JournalEntry {
  content: SecureContent           // Encrypted content support
  entryType: "real_time" | "backdated"
  privacyLevel: PrivacyLevel       // 6-tier privacy system
  securityClassification: SecurityClassification
  accessControlList?: string[]    // Explicit access DIDs
  location?: SecureLocation       // Optional encryption
  symptoms?: SecureSymptoms       // Required encryption for PHI
  evidenceUris?: string[]
  sourceIds?: string[]
  tags?: string[]
  auditMetadata?: AuditMetadata   // Access tracking
  // ... standard AT Protocol fields
}
```

**Key Features:**
- Flexible encryption based on classification level
- Comprehensive audit trail
- HIPAA-compliant PHI handling
- Tamper detection through digital signatures

### Privacy-Aware Feed (`xyz.tisocial.journal.feed`)

```typescript
interface FeedQuery {
  feedType: "personal" | "contacts" | "badge_community" | "public" | "anonymous"
  securityClassifications?: SecurityClassification[]
  badgeFilter?: BadgeType[]
  // ... filtering parameters
}
```

**Features:**
- Security classification filtering
- Badge-based community access
- Privacy-preserving query results
- Encrypted content placeholders in feeds

### Enhanced Privacy Controls (`xyz.tisocial.journal.privacy`)

```typescript
interface EnhancedPrivacyLevel {
  level: PrivacyLevel
  securityClassification: SecurityClassification
  allowedBadges?: BadgeType[]
  explicitAllowDids?: string[]
  explicitDenyDids?: string[]
  requireMFA?: boolean
  auditAllAccess?: boolean
}
```

**Features:**
- Multi-factor authentication requirements
- Explicit allow/deny lists
- Badge-based community permissions
- Automatic audit logging

## Security Framework Integration

### Privacy Levels

1. **Private** - User only
2. **Contacts** - Following/followers
3. **Badge Community** - Verified badge holders
4. **Public** - All users
5. **Anonymous** - Research purposes, no identifying info
6. **Medical** - PHI data with enhanced security

### Security Classifications

1. **Unclassified** - Standard content
2. **Sensitive** - Requires basic protection
3. **PHI** - Protected Health Information (HIPAA)
4. **Legal Evidence** - Tamper-proof, retention required
5. **Whistleblower** - Enhanced protection and anonymity

### Encryption Levels

1. **None** - Public content
2. **Standard** - AES-256 with user key
3. **Enhanced** - Double encryption with master key
4. **Quantum Resistant** - Post-quantum cryptography

## API Integration Examples

### Creating a Secure Journal Entry

```typescript
// Frontend React Query hook
const createEntry = useMutation({
  mutationFn: async (entryData) => {
    return await api.com.atproto.repo.createRecord({
      repo: session.did,
      collection: 'xyz.tisocial.journal.entry',
      record: {
        content: {
          text: entryData.text,
          isEncrypted: false,
          encryptionLevel: "none"
        },
        entryType: "real_time",
        privacyLevel: "badge_community",
        securityClassification: "sensitive",
        allowComments: true,
        allowSharing: false,
        createdAt: new Date().toISOString()
      }
    })
  }
})
```

### Querying Privacy-Aware Feed

```typescript
const journalFeed = useInfiniteQuery({
  queryKey: ['journal-feed', feedType, filters],
  queryFn: async ({ pageParam }) => {
    return await api.xyz.tisocial.journal.feed({
      feedType: 'badge_community',
      securityClassifications: ['unclassified', 'sensitive'],
      badgeFilter: ['havana', 'gangstalked'],
      cursor: pageParam,
      limit: 30
    })
  }
})
```

### Accessing Encrypted Content

```typescript
const getSecureEntry = useMutation({
  mutationFn: async (uri) => {
    const result = await api.xyz.tisocial.journal.entry.get({ uri })
    
    // Check if content requires decryption
    if (result.entry.content.isEncrypted) {
      // Frontend would handle decryption key management
      const decryptedContent = await decryptContent(
        result.entry.content.text,
        result.entry.content.encryptionMetadata
      )
      return {
        ...result,
        entry: {
          ...result.entry,
          content: {
            ...result.entry.content,
            text: decryptedContent
          }
        }
      }
    }
    
    return result
  }
})
```

## Privacy and Access Control

### Badge-Based Community Access

Users with verified badges can access entries shared with their badge community:

```typescript
// Check access permissions
const accessCheck = await api.xyz.tisocial.journal.privacy.checkAccess({
  entryUris: [entryUri],
  targetDid: userDid
})

if (accessCheck.accessResults[0].hasAccess) {
  // User can access this entry
  const accessLevel = accessCheck.accessResults[0].accessLevel // 'read', 'comment', 'share'
}
```

### Access Request Workflow

```typescript
// Request access to restricted entry
const requestAccess = await api.xyz.tisocial.journal.privacy.accessRequest({
  entryUri: restrictedEntryUri,
  requestReason: "Research collaboration on similar symptoms",
  requesterBadges: ["gangstalked", "targeted"]
})

// Entry owner responds to request
const respondToRequest = await api.xyz.tisocial.journal.privacy.respondToAccessRequest({
  requestId: requestAccess.requestId,
  response: "approve",
  grantLevel: "read",
  expiresAt: "2024-12-31T23:59:59Z"
})
```

## HIPAA Compliance Features

### PHI Data Handling

- **Automatic Encryption**: PHI classification requires enhanced encryption
- **Audit Logging**: All PHI access is logged with user, timestamp, action
- **Access Controls**: PHI cannot have public privacy level
- **MFA Requirements**: Optional multi-factor authentication for PHI access

### Audit Reports

```typescript
// Generate HIPAA compliance audit report
const auditReport = await api.xyz.tisocial.journal.analytics.getAuditReport({
  timeRange: {
    startTime: "2024-01-01T00:00:00Z",
    endTime: "2024-12-31T23:59:59Z"
  },
  auditTypes: ["phi_access", "privacy_changes", "security_alerts"],
  includeUserDetails: true // Requires elevated permissions
})
```

### Data Deletion

```typescript
// HIPAA-compliant data deletion
const deletionRequest = await api.xyz.tisocial.journal.analytics.requestDataDeletion({
  deletionScope: "phi_only",
  reason: "User requested PHI removal",
  retainForLegal: false
})
```

## Performance Considerations

### Encryption Impact

- **Feed Queries**: Encrypted content shows placeholders to avoid decryption overhead
- **Lazy Decryption**: Content decrypted only when explicitly accessed
- **Caching Strategy**: Decrypted content cached temporarily with secure session keys

### Database Optimization

- **Indexes**: Privacy level, security classification, badge types for efficient filtering
- **Query Patterns**: Pre-filter by access permissions before expensive operations
- **Audit Partitioning**: Separate audit tables by time periods for performance

## Security Monitoring

### Event Monitoring

The SecurityEventMonitor tracks:
- Rate limiting per user
- Suspicious access patterns 
- Bulk access attempts
- Failed authentication attempts

### Alert Thresholds

- **Rate Limit**: 100 requests per minute per user
- **PHI Access**: 10 PHI accesses triggers review
- **Bulk Access**: 50+ entries accessed rapidly triggers alert
- **Failed Access**: Multiple failed attempts on sensitive data

## Frontend Integration Patterns

### React Query Configuration

```typescript
// Configure React Query for journal data
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: (failureCount, error) => {
        // Don't retry on auth errors
        if (error.status === 401 || error.status === 403) {
          return false
        }
        return failureCount < 3
      }
    }
  }
})
```

### Error Handling

```typescript
// Handle security-related errors
const handleJournalError = (error) => {
  switch (error.name) {
    case 'InsufficientPermissions':
      // Show access request UI
      showAccessRequestDialog(error.requiredPermissions)
      break
    case 'EncryptionKeyRequired':
      // Prompt for decryption key
      showDecryptionKeyPrompt()
      break
    case 'HIPAAComplianceViolation':
      // Show compliance notice
      showComplianceNotice(error.violations)
      break
    default:
      showGenericError(error)
  }
}
```

## Testing and Development

### Mock Data Setup

```typescript
// Create mock journal entries for development
const mockEntries = [
  {
    content: { text: "Test entry", isEncrypted: false, encryptionLevel: "none" },
    privacyLevel: "public",
    securityClassification: "unclassified",
    entryType: "real_time"
  },
  {
    content: { text: "[ENCRYPTED]", isEncrypted: true, encryptionLevel: "enhanced" },
    privacyLevel: "medical",
    securityClassification: "phi",
    entryType: "backdated"
  }
]
```

### Integration Testing

```typescript
// Test privacy access controls
describe('Journal Privacy Controls', () => {
  test('PHI entries require appropriate permissions', async () => {
    const phiEntry = await createPHIEntry()
    const accessCheck = await checkAccess(phiEntry.uri, unprivilegedUser)
    expect(accessCheck.hasAccess).toBe(false)
    expect(accessCheck.reason).toContain('PHI access requires')
  })
})
```

## Deployment Considerations

### Environment Configuration

```bash
# Production environment variables
JOURNAL_ENCRYPTION_KEY_ID="prod-key-v1"
HIPAA_AUDIT_RETENTION_DAYS="2555" # 7 years
PHI_ACCESS_LOG_ENABLED="true"
MFA_REQUIRED_FOR_PHI="true"
SECURITY_MONITORING_ENABLED="true"
```

### Monitoring and Alerts

- Set up alerts for HIPAA compliance violations
- Monitor encryption key rotation schedules
- Track audit log storage and retention
- Alert on suspicious access patterns

## Summary

The TISocial journal system provides a comprehensive, secure platform for sensitive data with:

- **Multi-tier privacy controls** ensuring appropriate data access
- **HIPAA compliance** for medical information handling  
- **Flexible encryption** based on data sensitivity
- **Comprehensive audit trails** for security and compliance
- **Badge-based community features** for peer support
- **Performance optimization** for large-scale deployment

All components are designed to integrate seamlessly with the AT Protocol while providing enhanced security and privacy features required for the targeted individual community.