/**
 * Enhanced Authentication and Authorization Framework
 * 
 * Implements multi-factor authentication, role-based access control,
 * session management, and badge verification integration.
 */

import { randomBytes, createHash, timingSafeEqual } from 'node:crypto'
import { httpLogger as logger } from '../logger'
// import { HIPAAComplianceManager } from '../journal-security' // TODO: Re-enable when PHI support is added

// Authentication levels
export enum AuthLevel {
  BASIC = 'basic',           // Password only
  MFA = 'mfa',              // Multi-factor authenticated
  BIOMETRIC = 'biometric',   // Biometric + MFA
  HARDWARE = 'hardware',     // Hardware token required
}

// User roles
export enum UserRole {
  USER = 'user',                    // Basic user
  VERIFIED_VICTIM = 'verified_victim', // Badge holder
  MODERATOR = 'moderator',          // Community moderator
  RESEARCHER = 'researcher',        // Data researcher
  ADMIN = 'admin',                 // System administrator
  SUPER_ADMIN = 'super_admin',     // Super administrator
}

// Session status
export enum SessionStatus {
  ACTIVE = 'active',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
  SUSPENDED = 'suspended',
}

// MFA method types
export enum MFAMethod {
  TOTP = 'totp',           // Time-based OTP (Google Authenticator)
  SMS = 'sms',             // SMS verification
  EMAIL = 'email',         // Email verification
  HARDWARE = 'hardware',   // Hardware token (YubiKey)
  BIOMETRIC = 'biometric', // Biometric verification
}

// Authentication context
export interface AuthContext {
  userDid: string
  sessionId: string
  authLevel: AuthLevel
  roles: UserRole[]
  permissions: string[]
  mfaVerified: boolean
  mfaMethods: MFAMethod[]
  ipAddress?: string
  userAgent?: string
  deviceFingerprint?: string
  lastActivity: number
  createdAt: number
  expiresAt: number
}

// Session data
export interface SessionData {
  id: string
  userDid: string
  status: SessionStatus
  authLevel: AuthLevel
  ipAddress?: string
  userAgent?: string
  deviceFingerprint?: string
  createdAt: number
  lastActivity: number
  expiresAt: number
  metadata?: Record<string, any>
}

// MFA challenge
export interface MFAChallenge {
  challengeId: string
  userDid: string
  method: MFAMethod
  code?: string // For verification
  expiresAt: number
  attempts: number
  maxAttempts: number
}

// Authentication result
export interface AuthResult {
  success: boolean
  authContext?: AuthContext
  requiresMFA?: boolean
  mfaChallenge?: MFAChallenge
  error?: string
  lockoutUntil?: number
}

// Permission definition
export interface Permission {
  id: string
  name: string
  description: string
  category: 'read' | 'write' | 'admin' | 'special'
  requiresAuth: AuthLevel
  requiredRoles?: UserRole[]
}

/**
 * Enhanced Authentication Manager
 */
export class EnhancedAuthManager {
  private static instance: EnhancedAuthManager
  private sessions: Map<string, SessionData> = new Map()
  private mfaChallenges: Map<string, MFAChallenge> = new Map()
  private failedAttempts: Map<string, { count: number; lockoutUntil?: number }> = new Map()
  private permissions: Map<string, Permission> = new Map()

  // Rate limiting configuration
  private static readonly MAX_LOGIN_ATTEMPTS = 5
  private static readonly LOCKOUT_DURATION = 15 * 60 * 1000 // 15 minutes
  private static readonly SESSION_TIMEOUT = 4 * 60 * 60 * 1000 // 4 hours
  private static readonly MFA_TIMEOUT = 5 * 60 * 1000 // 5 minutes

  public static getInstance(): EnhancedAuthManager {
    if (!EnhancedAuthManager.instance) {
      EnhancedAuthManager.instance = new EnhancedAuthManager()
      EnhancedAuthManager.instance.initializePermissions()
    }
    return EnhancedAuthManager.instance
  }

  /**
   * Initialize system permissions
   */
  private initializePermissions(): void {
    const permissions: Permission[] = [
      // Basic permissions
      { id: 'journal:read:own', name: 'Read Own Journal', description: 'Read own journal entries', category: 'read', requiresAuth: AuthLevel.BASIC },
      { id: 'journal:write:own', name: 'Write Own Journal', description: 'Create/edit own journal entries', category: 'write', requiresAuth: AuthLevel.BASIC },
      
      // Community permissions
      { id: 'journal:read:community', name: 'Read Community Journals', description: 'Read community journal entries', category: 'read', requiresAuth: AuthLevel.BASIC, requiredRoles: [UserRole.VERIFIED_VICTIM] },
      
      // Medical permissions (PHI access)
      { id: 'medical:read', name: 'Read Medical Data', description: 'Access medical information', category: 'read', requiresAuth: AuthLevel.MFA },
      { id: 'phi:access', name: 'PHI Access', description: 'Access protected health information', category: 'special', requiresAuth: AuthLevel.MFA },
      
      // Legal permissions
      { id: 'legal:evidence:access', name: 'Legal Evidence Access', description: 'Access legal evidence', category: 'special', requiresAuth: AuthLevel.MFA },
      { id: 'legal:evidence:create', name: 'Create Legal Evidence', description: 'Create legal evidence entries', category: 'write', requiresAuth: AuthLevel.HARDWARE },
      
      // Research permissions
      { id: 'research:data:access', name: 'Research Data Access', description: 'Access anonymized research data', category: 'read', requiresAuth: AuthLevel.MFA, requiredRoles: [UserRole.RESEARCHER] },
      
      // Administrative permissions
      { id: 'admin:user:manage', name: 'User Management', description: 'Manage user accounts', category: 'admin', requiresAuth: AuthLevel.HARDWARE, requiredRoles: [UserRole.ADMIN] },
      { id: 'admin:system:config', name: 'System Configuration', description: 'Configure system settings', category: 'admin', requiresAuth: AuthLevel.HARDWARE, requiredRoles: [UserRole.SUPER_ADMIN] },
    ]

    permissions.forEach(perm => this.permissions.set(perm.id, perm))
  }

  /**
   * Authenticate user with enhanced security
   */
  public async authenticate(credentials: {
    userDid: string
    password?: string
    mfaCode?: string
    challengeId?: string
    biometricData?: string
    ipAddress?: string
    userAgent?: string
    deviceFingerprint?: string
  }): Promise<AuthResult> {
    const { userDid, ipAddress, userAgent, deviceFingerprint } = credentials

    try {
      // Check for account lockout
      const lockoutCheck = this.checkAccountLockout(userDid, ipAddress)
      if (lockoutCheck.locked) {
        return {
          success: false,
          error: 'Account temporarily locked due to failed attempts',
          lockoutUntil: lockoutCheck.lockoutUntil,
        }
      }

      // Basic password authentication
      if (credentials.password) {
        const passwordValid = await this.verifyPassword(userDid, credentials.password)
        if (!passwordValid) {
          this.recordFailedAttempt(userDid, ipAddress)
          return {
            success: false,
            error: 'Invalid credentials',
          }
        }

        // Check if MFA is required
        const user = await this.getUserData(userDid)
        if (user.mfaEnabled) {
          const challenge = this.createMFAChallenge(userDid, user.preferredMFAMethod)
          return {
            success: false,
            requiresMFA: true,
            mfaChallenge: challenge,
          }
        }

        // Create session for basic auth
        const session = await this.createSession(userDid, AuthLevel.BASIC, {
          ipAddress,
          userAgent,
          deviceFingerprint,
        })

        return {
          success: true,
          authContext: await this.buildAuthContext(session),
        }
      }

      // MFA verification
      if (credentials.mfaCode && credentials.challengeId) {
        const mfaResult = await this.verifyMFA(credentials.challengeId, credentials.mfaCode)
        if (!mfaResult.success) {
          this.recordFailedAttempt(userDid, ipAddress)
          return {
            success: false,
            error: 'Invalid MFA code',
          }
        }

        // Create MFA session
        const session = await this.createSession(userDid, AuthLevel.MFA, {
          ipAddress,
          userAgent,
          deviceFingerprint,
        })

        return {
          success: true,
          authContext: await this.buildAuthContext(session),
        }
      }

      // Biometric authentication
      if (credentials.biometricData) {
        const biometricValid = await this.verifyBiometric(userDid, credentials.biometricData)
        if (!biometricValid) {
          this.recordFailedAttempt(userDid, ipAddress)
          return {
            success: false,
            error: 'Biometric verification failed',
          }
        }

        // Create biometric session
        const session = await this.createSession(userDid, AuthLevel.BIOMETRIC, {
          ipAddress,
          userAgent,
          deviceFingerprint,
        })

        return {
          success: true,
          authContext: await this.buildAuthContext(session),
        }
      }

      return {
        success: false,
        error: 'Invalid authentication method',
      }

    } catch (error) {
      logger.error('Authentication error', { error, userDid, ipAddress })
      return {
        success: false,
        error: 'Authentication failed',
      }
    }
  }

  /**
   * Create MFA challenge
   */
  private createMFAChallenge(userDid: string, method: MFAMethod): MFAChallenge {
    const challengeId = this.generateSecureId()
    const challenge: MFAChallenge = {
      challengeId,
      userDid,
      method,
      expiresAt: Date.now() + EnhancedAuthManager.MFA_TIMEOUT,
      attempts: 0,
      maxAttempts: 3,
    }

    this.mfaChallenges.set(challengeId, challenge)

    // Send challenge via appropriate method
    this.sendMFAChallenge(challenge)

    return challenge
  }

  /**
   * Verify MFA code
   */
  private async verifyMFA(challengeId: string, code: string): Promise<{ success: boolean; error?: string }> {
    const challenge = this.mfaChallenges.get(challengeId)
    if (!challenge) {
      return { success: false, error: 'Invalid challenge' }
    }

    if (Date.now() > challenge.expiresAt) {
      this.mfaChallenges.delete(challengeId)
      return { success: false, error: 'Challenge expired' }
    }

    if (challenge.attempts >= challenge.maxAttempts) {
      this.mfaChallenges.delete(challengeId)
      return { success: false, error: 'Too many attempts' }
    }

    challenge.attempts++

    // Verify code based on method
    let isValid = false
    switch (challenge.method) {
      case MFAMethod.TOTP:
        isValid = await this.verifyTOTP(challenge.userDid, code)
        break
      case MFAMethod.SMS:
        isValid = challenge.code === code
        break
      case MFAMethod.EMAIL:
        isValid = challenge.code === code
        break
      case MFAMethod.HARDWARE:
        isValid = await this.verifyHardwareToken(challenge.userDid, code)
        break
    }

    if (isValid) {
      this.mfaChallenges.delete(challengeId)
      return { success: true }
    }

    return { success: false, error: 'Invalid code' }
  }

  /**
   * Create authenticated session
   */
  public async createSession(
    userDid: string,
    authLevel: AuthLevel,
    metadata?: Record<string, any>
  ): Promise<SessionData> {
    const sessionId = this.generateSecureId()
    const now = Date.now()

    const session: SessionData = {
      id: sessionId,
      userDid,
      status: SessionStatus.ACTIVE,
      authLevel,
      createdAt: now,
      lastActivity: now,
      expiresAt: now + EnhancedAuthManager.SESSION_TIMEOUT,
      metadata,
      ...metadata,
    }

    this.sessions.set(sessionId, session)

    // Log session creation
    logger.info('Session created', {
      sessionId,
      userDid,
      authLevel,
      ipAddress: metadata?.ipAddress,
    })

    return session
  }

  /**
   * Validate session and return auth context
   */
  public async validateSession(sessionId: string): Promise<AuthContext | null> {
    const session = this.sessions.get(sessionId)
    if (!session) {
      return null
    }

    const now = Date.now()

    // Check session expiry
    if (now > session.expiresAt || session.status !== SessionStatus.ACTIVE) {
      this.revokeSession(sessionId)
      return null
    }

    // Update last activity
    session.lastActivity = now

    return this.buildAuthContext(session)
  }

  /**
   * Build authentication context from session
   */
  private async buildAuthContext(session: SessionData): Promise<AuthContext> {
    const user = await this.getUserData(session.userDid)
    const permissions = await this.getUserPermissions(session.userDid, user.roles)

    return {
      userDid: session.userDid,
      sessionId: session.id,
      authLevel: session.authLevel,
      roles: user.roles,
      permissions,
      mfaVerified: session.authLevel === AuthLevel.MFA || session.authLevel === AuthLevel.BIOMETRIC,
      mfaMethods: user.mfaMethods,
      ipAddress: session.ipAddress,
      userAgent: session.userAgent,
      deviceFingerprint: session.deviceFingerprint,
      lastActivity: session.lastActivity,
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
    }
  }

  /**
   * Check user permissions for operation
   */
  public async checkPermission(
    authContext: AuthContext,
    permissionId: string
  ): Promise<{ allowed: boolean; reason?: string }> {
    const permission = this.permissions.get(permissionId)
    if (!permission) {
      return { allowed: false, reason: 'Unknown permission' }
    }

    // Check authentication level
    if (!this.hasRequiredAuthLevel(authContext.authLevel, permission.requiresAuth)) {
      return {
        allowed: false,
        reason: `Requires ${permission.requiresAuth} authentication level`,
      }
    }

    // Check role requirements
    if (permission.requiredRoles && permission.requiredRoles.length > 0) {
      const hasRequiredRole = permission.requiredRoles.some(role =>
        authContext.roles.includes(role)
      )

      if (!hasRequiredRole) {
        return {
          allowed: false,
          reason: `Requires one of: ${permission.requiredRoles.join(', ')}`,
        }
      }
    }

    // Check if user has explicit permission
    if (!authContext.permissions.includes(permissionId)) {
      return { allowed: false, reason: 'Permission not granted' }
    }

    // TODO: Add PHI access logging when HIPAA support is implemented

    return { allowed: true }
  }

  /**
   * Revoke session
   */
  public revokeSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId)
    if (session) {
      session.status = SessionStatus.REVOKED
      logger.info('Session revoked', { sessionId, userDid: session.userDid })
      return true
    }
    return false
  }

  /**
   * Revoke all sessions for user
   */
  public revokeAllUserSessions(userDid: string): number {
    let revokedCount = 0
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.userDid === userDid && session.status === SessionStatus.ACTIVE) {
        session.status = SessionStatus.REVOKED
        revokedCount++
      }
    }

    logger.info('All user sessions revoked', { userDid, count: revokedCount })
    return revokedCount
  }

  /**
   * Check account lockout status
   */
  private checkAccountLockout(
    userDid: string,
    ipAddress?: string
  ): { locked: boolean; lockoutUntil?: number } {
    const userKey = `user:${userDid}`
    const ipKey = ipAddress ? `ip:${ipAddress}` : null

    const now = Date.now()
    
    // Check user lockout
    const userAttempts = this.failedAttempts.get(userKey)
    if (userAttempts?.lockoutUntil && now < userAttempts.lockoutUntil) {
      return { locked: true, lockoutUntil: userAttempts.lockoutUntil }
    }

    // Check IP lockout
    if (ipKey) {
      const ipAttempts = this.failedAttempts.get(ipKey)
      if (ipAttempts?.lockoutUntil && now < ipAttempts.lockoutUntil) {
        return { locked: true, lockoutUntil: ipAttempts.lockoutUntil }
      }
    }

    return { locked: false }
  }

  /**
   * Record failed authentication attempt
   */
  private recordFailedAttempt(userDid: string, ipAddress?: string): void {
    const now = Date.now()
    const userKey = `user:${userDid}`
    const ipKey = ipAddress ? `ip:${ipAddress}` : null

    // Record user attempt
    const userAttempts = this.failedAttempts.get(userKey) || { count: 0 }
    userAttempts.count++

    if (userAttempts.count >= EnhancedAuthManager.MAX_LOGIN_ATTEMPTS) {
      userAttempts.lockoutUntil = now + EnhancedAuthManager.LOCKOUT_DURATION
    }

    this.failedAttempts.set(userKey, userAttempts)

    // Record IP attempt
    if (ipKey) {
      const ipAttempts = this.failedAttempts.get(ipKey) || { count: 0 }
      ipAttempts.count++

      if (ipAttempts.count >= EnhancedAuthManager.MAX_LOGIN_ATTEMPTS * 3) {
        ipAttempts.lockoutUntil = now + EnhancedAuthManager.LOCKOUT_DURATION * 2
      }

      this.failedAttempts.set(ipKey, ipAttempts)
    }

    logger.warn('Failed authentication attempt', {
      userDid,
      ipAddress,
      attempts: userAttempts.count,
      locked: !!userAttempts.lockoutUntil,
    })
  }

  /**
   * Clear failed attempts for successful login
   */
  private clearFailedAttempts(userDid: string, ipAddress?: string): void {
    const userKey = `user:${userDid}`
    const ipKey = ipAddress ? `ip:${ipAddress}` : null

    this.failedAttempts.delete(userKey)
    if (ipKey) {
      this.failedAttempts.delete(ipKey)
    }
  }

  /**
   * Check if user has required authentication level
   */
  private hasRequiredAuthLevel(userLevel: AuthLevel, requiredLevel: AuthLevel): boolean {
    const levelHierarchy = {
      [AuthLevel.BASIC]: 1,
      [AuthLevel.MFA]: 2,
      [AuthLevel.BIOMETRIC]: 3,
      [AuthLevel.HARDWARE]: 4,
    }

    return levelHierarchy[userLevel] >= levelHierarchy[requiredLevel]
  }

  /**
   * Generate secure session/challenge ID
   */
  private generateSecureId(): string {
    return randomBytes(32).toString('hex')
  }

  // Placeholder methods for integration with external systems

  private async verifyPassword(userDid: string, password: string): Promise<boolean> {
    // Implementation would verify against stored password hash
    return true // Placeholder
  }

  private async verifyBiometric(userDid: string, biometricData: string): Promise<boolean> {
    // Implementation would verify biometric data
    return true // Placeholder
  }

  private async verifyTOTP(userDid: string, code: string): Promise<boolean> {
    // Implementation would verify TOTP code
    return true // Placeholder
  }

  private async verifyHardwareToken(userDid: string, token: string): Promise<boolean> {
    // Implementation would verify hardware token
    return true // Placeholder
  }

  private async sendMFAChallenge(challenge: MFAChallenge): Promise<void> {
    // Implementation would send MFA challenge via appropriate method
    logger.info('MFA challenge sent', {
      challengeId: challenge.challengeId,
      method: challenge.method,
      userDid: challenge.userDid,
    })
  }

  private async getUserData(userDid: string): Promise<{
    roles: UserRole[]
    mfaEnabled: boolean
    preferredMFAMethod: MFAMethod
    mfaMethods: MFAMethod[]
  }> {
    // Implementation would fetch user data from database
    return {
      roles: [UserRole.USER],
      mfaEnabled: false,
      preferredMFAMethod: MFAMethod.TOTP,
      mfaMethods: [MFAMethod.TOTP],
    }
  }

  private async getUserPermissions(userDid: string, roles: UserRole[]): Promise<string[]> {
    // Implementation would determine user permissions based on roles
    const basePermissions = ['journal:read:own', 'journal:write:own']
    
    if (roles.includes(UserRole.VERIFIED_VICTIM)) {
      basePermissions.push('journal:read:community')
    }

    return basePermissions
  }
}

/**
 * Role-Based Access Control (RBAC) Manager
 */
export class RBACManager {
  private roleHierarchy: Map<UserRole, UserRole[]> = new Map()
  private rolePermissions: Map<UserRole, string[]> = new Map()

  constructor() {
    this.initializeRoleHierarchy()
    this.initializeRolePermissions()
  }

  /**
   * Initialize role hierarchy (inheritance)
   */
  private initializeRoleHierarchy(): void {
    this.roleHierarchy.set(UserRole.SUPER_ADMIN, [
      UserRole.ADMIN,
      UserRole.MODERATOR,
      UserRole.RESEARCHER,
      UserRole.VERIFIED_VICTIM,
      UserRole.USER,
    ])

    this.roleHierarchy.set(UserRole.ADMIN, [
      UserRole.MODERATOR,
      UserRole.RESEARCHER,
      UserRole.VERIFIED_VICTIM,
      UserRole.USER,
    ])

    this.roleHierarchy.set(UserRole.MODERATOR, [
      UserRole.VERIFIED_VICTIM,
      UserRole.USER,
    ])

    this.roleHierarchy.set(UserRole.RESEARCHER, [
      UserRole.USER,
    ])

    this.roleHierarchy.set(UserRole.VERIFIED_VICTIM, [
      UserRole.USER,
    ])
  }

  /**
   * Initialize role permissions
   */
  private initializeRolePermissions(): void {
    this.rolePermissions.set(UserRole.USER, [
      'journal:read:own',
      'journal:write:own',
    ])

    this.rolePermissions.set(UserRole.VERIFIED_VICTIM, [
      'journal:read:community',
    ])

    this.rolePermissions.set(UserRole.RESEARCHER, [
      'research:data:access',
    ])

    this.rolePermissions.set(UserRole.MODERATOR, [
      'journal:read:community',
      'moderation:content:flag',
      'moderation:content:hide',
    ])

    this.rolePermissions.set(UserRole.ADMIN, [
      'admin:user:manage',
      'medical:read',
      'phi:access',
      'legal:evidence:access',
    ])

    this.rolePermissions.set(UserRole.SUPER_ADMIN, [
      'admin:system:config',
      'legal:evidence:create',
    ])
  }

  /**
   * Get all permissions for user roles
   */
  public getUserPermissions(roles: UserRole[]): string[] {
    const permissions = new Set<string>()

    for (const role of roles) {
      // Add direct permissions
      const rolePerms = this.rolePermissions.get(role) || []
      rolePerms.forEach(perm => permissions.add(perm))

      // Add inherited permissions
      const inheritedRoles = this.roleHierarchy.get(role) || []
      for (const inheritedRole of inheritedRoles) {
        const inheritedPerms = this.rolePermissions.get(inheritedRole) || []
        inheritedPerms.forEach(perm => permissions.add(perm))
      }
    }

    return Array.from(permissions)
  }
}