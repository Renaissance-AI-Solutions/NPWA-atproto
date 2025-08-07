/**
 * Comprehensive Input Validation and Sanitization Framework
 * 
 * Provides defense-in-depth input validation for all journal entry fields,
 * XSS/injection prevention, and file upload security.
 */

import DOMPurify from 'isomorphic-dompurify'
import validator from 'validator'
import { httpLogger as logger } from '../logger'

// Validation severity levels
export enum ValidationSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

// Input validation result
export interface ValidationResult {
  isValid: boolean
  sanitizedValue?: any
  errors: ValidationError[]
  warnings: ValidationWarning[]
  metadata?: Record<string, any>
}

export interface ValidationError {
  field: string
  message: string
  severity: ValidationSeverity
  code: string
  input?: string
}

export interface ValidationWarning {
  field: string
  message: string
  recommendation: string
}

// Content security policy configuration
export interface ContentSecurityConfig {
  allowedHtmlTags: string[]
  allowedAttributes: string[]
  maxLength: number
  forbiddenPatterns: RegExp[]
  requiredPatterns?: RegExp[]
}

// File validation configuration
export interface FileValidationConfig {
  allowedMimeTypes: string[]
  maxFileSize: number // bytes
  maxFilesPerEntry: number
  virusScanRequired: boolean
  encryptionRequired: boolean
}

/**
 * Advanced Input Validator with security-first approach
 */
export class AdvancedInputValidator {
  private static readonly PHI_PATTERNS = [
    /\b\d{3}-\d{2}-\d{4}\b/, // SSN pattern
    /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, // Credit card pattern
    /\b[A-Z]{2}\d{7}\b/, // Medical record number pattern
    /\b\d{10}\b/, // Generic 10-digit ID
  ]

  private static readonly XSS_PATTERNS = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload=/gi,
    /onerror=/gi,
    /onclick=/gi,
    /onmouseover=/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
  ]

  private static readonly SQL_INJECTION_PATTERNS = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/gi,
    /('|(\\x27)|(\\x2D\\x2D)|(%27)|(%2D%2D))/gi,
    /((\%3D)|(=))[^\n]*((\%27)|(\\x27)|(')).*((\%3B)|(;))/gi,
  ]

  private static readonly CONTENT_SECURITY_CONFIGS: Record<string, ContentSecurityConfig> = {
    journal_text: {
      allowedHtmlTags: ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li'],
      allowedAttributes: [],
      maxLength: 10000,
      forbiddenPatterns: AdvancedInputValidator.XSS_PATTERNS,
    },
    user_input: {
      allowedHtmlTags: [],
      allowedAttributes: [],
      maxLength: 1000,
      forbiddenPatterns: [...AdvancedInputValidator.XSS_PATTERNS, ...AdvancedInputValidator.SQL_INJECTION_PATTERNS],
    },
    location_data: {
      allowedHtmlTags: [],
      allowedAttributes: [],
      maxLength: 200,
      forbiddenPatterns: [],
      requiredPatterns: [/^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$/], // lat,lng format
    },
  }

  /**
   * Validate and sanitize journal entry content
   */
  public static validateJournalEntry(entry: any): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []
    const sanitizedEntry: any = {}

    // Validate required fields
    if (!entry.content?.text) {
      errors.push({
        field: 'content.text',
        message: 'Journal entry text is required',
        severity: ValidationSeverity.ERROR,
        code: 'REQUIRED_FIELD_MISSING',
      })
    }

    // Validate and sanitize content text
    if (entry.content?.text) {
      const textValidation = this.validateAndSanitizeText(
        entry.content.text,
        'journal_text'
      )
      
      if (!textValidation.isValid) {
        errors.push(...textValidation.errors)
      }
      
      warnings.push(...textValidation.warnings)
      sanitizedEntry.content = {
        ...entry.content,
        text: textValidation.sanitizedValue,
      }

      // Check for PHI data
      const phiDetection = this.detectPHI(entry.content.text)
      if (phiDetection.detected) {
        warnings.push({
          field: 'content.text',
          message: 'Potential PHI detected - ensure proper classification',
          recommendation: 'Set privacy level to MEDICAL and classification to PHI',
        })
      }
    }

    // Validate privacy level
    if (entry.privacyLevel) {
      const privacyValidation = this.validatePrivacyLevel(entry.privacyLevel, entry.classification)
      if (!privacyValidation.isValid) {
        errors.push(...privacyValidation.errors)
      }
    }

    // Validate location data
    if (entry.location) {
      const locationValidation = this.validateLocationData(entry.location)
      if (!locationValidation.isValid) {
        errors.push(...locationValidation.errors)
      } else {
        sanitizedEntry.location = locationValidation.sanitizedValue
      }
    }

    // Validate symptoms data
    if (entry.symptoms) {
      const symptomsValidation = this.validateSymptomsData(entry.symptoms)
      if (!symptomsValidation.isValid) {
        errors.push(...symptomsValidation.errors)
      } else {
        sanitizedEntry.symptoms = symptomsValidation.sanitizedValue
      }
    }

    // Validate evidence URIs
    if (entry.evidenceUris && Array.isArray(entry.evidenceUris)) {
      const evidenceValidation = this.validateEvidenceUris(entry.evidenceUris)
      if (!evidenceValidation.isValid) {
        errors.push(...evidenceValidation.errors)
      } else {
        sanitizedEntry.evidenceUris = evidenceValidation.sanitizedValue
      }
    }

    // Validate tags
    if (entry.tags && Array.isArray(entry.tags)) {
      const tagsValidation = this.validateTags(entry.tags)
      if (!tagsValidation.isValid) {
        errors.push(...tagsValidation.errors)
      } else {
        sanitizedEntry.tags = tagsValidation.sanitizedValue
      }
    }

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedEntry,
      errors,
      warnings,
      metadata: {
        validatedAt: new Date().toISOString(),
        validationVersion: '1.0.0',
      },
    }
  }

  /**
   * Validate and sanitize text content with security filtering
   */
  public static validateAndSanitizeText(
    text: string,
    configType: keyof typeof AdvancedInputValidator.CONTENT_SECURITY_CONFIGS
  ): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []
    const config = this.CONTENT_SECURITY_CONFIGS[configType]

    if (!text || typeof text !== 'string') {
      errors.push({
        field: 'text',
        message: 'Text content must be a non-empty string',
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_TEXT_TYPE',
      })
      return { isValid: false, errors, warnings }
    }

    // Length validation
    if (text.length > config.maxLength) {
      errors.push({
        field: 'text',
        message: `Text exceeds maximum length of ${config.maxLength} characters`,
        severity: ValidationSeverity.ERROR,
        code: 'TEXT_TOO_LONG',
        input: text.substring(0, 100) + '...',
      })
    }

    // Pattern validation
    for (const pattern of config.forbiddenPatterns) {
      if (pattern.test(text)) {
        errors.push({
          field: 'text',
          message: 'Text contains forbidden patterns (potential XSS/injection)',
          severity: ValidationSeverity.CRITICAL,
          code: 'FORBIDDEN_PATTERN_DETECTED',
          input: this.maskSensitiveContent(text),
        })
      }
    }

    // Required pattern validation
    if (config.requiredPatterns) {
      for (const pattern of config.requiredPatterns) {
        if (!pattern.test(text)) {
          errors.push({
            field: 'text',
            message: 'Text does not match required format',
            severity: ValidationSeverity.ERROR,
            code: 'INVALID_FORMAT',
          })
        }
      }
    }

    // Sanitize HTML content
    let sanitizedText = text
    try {
      sanitizedText = DOMPurify.sanitize(text, {
        ALLOWED_TAGS: config.allowedHtmlTags,
        ALLOWED_ATTR: config.allowedAttributes,
        KEEP_CONTENT: true,
      })

      if (sanitizedText !== text) {
        warnings.push({
          field: 'text',
          message: 'HTML content was sanitized',
          recommendation: 'Review sanitized content for unintended changes',
        })
      }
    } catch (error) {
      errors.push({
        field: 'text',
        message: 'Failed to sanitize HTML content',
        severity: ValidationSeverity.ERROR,
        code: 'SANITIZATION_FAILED',
      })
    }

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedText,
      errors,
      warnings,
    }
  }

  /**
   * Validate privacy level and classification consistency
   */
  public static validatePrivacyLevel(
    privacyLevel: string,
    classification?: string
  ): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    const validPrivacyLevels = ['public', 'community', 'private', 'medical', 'legal', 'anonymous']
    const validClassifications = ['unclassified', 'sensitive', 'phi', 'legal_evidence', 'whistleblower']

    if (!validPrivacyLevels.includes(privacyLevel)) {
      errors.push({
        field: 'privacyLevel',
        message: `Invalid privacy level. Must be one of: ${validPrivacyLevels.join(', ')}`,
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_PRIVACY_LEVEL',
      })
    }

    if (classification && !validClassifications.includes(classification)) {
      errors.push({
        field: 'classification',
        message: `Invalid classification. Must be one of: ${validClassifications.join(', ')}`,
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_CLASSIFICATION',
      })
    }

    // Validate consistency between privacy level and classification
    if (classification === 'phi' && privacyLevel === 'public') {
      errors.push({
        field: 'privacyLevel',
        message: 'PHI data cannot have public privacy level',
        severity: ValidationSeverity.CRITICAL,
        code: 'PHI_PRIVACY_VIOLATION',
      })
    }

    if (privacyLevel === 'medical' && classification !== 'phi') {
      warnings.push({
        field: 'classification',
        message: 'Medical privacy level typically requires PHI classification',
        recommendation: 'Consider setting classification to PHI for proper HIPAA compliance',
      })
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    }
  }

  /**
   * Validate location data format and security
   */
  public static validateLocationData(location: any): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    if (!location || typeof location !== 'object') {
      errors.push({
        field: 'location',
        message: 'Location data must be an object',
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_LOCATION_TYPE',
      })
      return { isValid: false, errors, warnings }
    }

    const sanitizedLocation: any = { ...location }

    // Validate coordinates if present
    if (location.latitude !== undefined || location.longitude !== undefined) {
      if (
        typeof location.latitude !== 'number' ||
        typeof location.longitude !== 'number' ||
        location.latitude < -90 ||
        location.latitude > 90 ||
        location.longitude < -180 ||
        location.longitude > 180
      ) {
        errors.push({
          field: 'location.coordinates',
          message: 'Invalid latitude/longitude coordinates',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_COORDINATES',
        })
      }
    }

    // Validate address
    if (location.address && typeof location.address === 'string') {
      const addressValidation = this.validateAndSanitizeText(location.address, 'user_input')
      if (!addressValidation.isValid) {
        errors.push(...addressValidation.errors.map(err => ({
          ...err,
          field: `location.${err.field}`,
        })))
      } else {
        sanitizedLocation.address = addressValidation.sanitizedValue
      }
    }

    // Check for high-precision coordinates (privacy concern)
    if (location.accuracy && location.accuracy < 10) {
      warnings.push({
        field: 'location.accuracy',
        message: 'High-precision location data detected',
        recommendation: 'Consider reducing precision for privacy protection',
      })
    }

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedLocation,
      errors,
      warnings,
    }
  }

  /**
   * Validate symptoms data structure and content
   */
  public static validateSymptomsData(symptoms: any): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    if (!Array.isArray(symptoms)) {
      errors.push({
        field: 'symptoms',
        message: 'Symptoms must be an array',
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_SYMPTOMS_TYPE',
      })
      return { isValid: false, errors, warnings }
    }

    const sanitizedSymptoms = symptoms.map((symptom, index) => {
      if (typeof symptom !== 'string') {
        errors.push({
          field: `symptoms[${index}]`,
          message: 'Each symptom must be a string',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_SYMPTOM_TYPE',
        })
        return symptom
      }

      const validation = this.validateAndSanitizeText(symptom, 'user_input')
      if (!validation.isValid) {
        errors.push(...validation.errors.map(err => ({
          ...err,
          field: `symptoms[${index}].${err.field}`,
        })))
      }

      return validation.sanitizedValue || symptom
    })

    // Limit number of symptoms
    if (symptoms.length > 50) {
      errors.push({
        field: 'symptoms',
        message: 'Too many symptoms listed (maximum 50)',
        severity: ValidationSeverity.ERROR,
        code: 'TOO_MANY_SYMPTOMS',
      })
    }

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedSymptoms,
      errors,
      warnings,
    }
  }

  /**
   * Validate evidence URIs for security and format
   */
  public static validateEvidenceUris(uris: string[]): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    if (!Array.isArray(uris)) {
      errors.push({
        field: 'evidenceUris',
        message: 'Evidence URIs must be an array',
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_EVIDENCE_TYPE',
      })
      return { isValid: false, errors, warnings }
    }

    // Limit number of evidence files
    if (uris.length > 20) {
      errors.push({
        field: 'evidenceUris',
        message: 'Too many evidence files (maximum 20)',
        severity: ValidationSeverity.ERROR,
        code: 'TOO_MANY_EVIDENCE_FILES',
      })
    }

    const sanitizedUris = uris.map((uri, index) => {
      if (typeof uri !== 'string') {
        errors.push({
          field: `evidenceUris[${index}]`,
          message: 'Evidence URI must be a string',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_URI_TYPE',
        })
        return uri
      }

      // Validate URI format
      if (!validator.isURL(uri, { require_protocol: true, protocols: ['https', 'at'] })) {
        errors.push({
          field: `evidenceUris[${index}]`,
          message: 'Invalid URI format - must be HTTPS or AT Protocol URI',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_URI_FORMAT',
        })
      }

      // Check for suspicious URLs
      if (this.isSuspiciousUrl(uri)) {
        warnings.push({
          field: `evidenceUris[${index}]`,
          message: 'Potentially suspicious URL detected',
          recommendation: 'Verify URL safety before accessing',
        })
      }

      return uri
    })

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedUris,
      errors,
      warnings,
    }
  }

  /**
   * Validate tags for content and security
   */
  public static validateTags(tags: string[]): ValidationResult {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    if (!Array.isArray(tags)) {
      errors.push({
        field: 'tags',
        message: 'Tags must be an array',
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_TAGS_TYPE',
      })
      return { isValid: false, errors, warnings }
    }

    // Limit number of tags
    if (tags.length > 20) {
      errors.push({
        field: 'tags',
        message: 'Too many tags (maximum 20)',
        severity: ValidationSeverity.ERROR,
        code: 'TOO_MANY_TAGS',
      })
    }

    const sanitizedTags = tags.map((tag, index) => {
      if (typeof tag !== 'string') {
        errors.push({
          field: `tags[${index}]`,
          message: 'Each tag must be a string',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_TAG_TYPE',
        })
        return tag
      }

      // Validate tag format
      const sanitizedTag = tag.trim().toLowerCase()
      
      if (sanitizedTag.length === 0) {
        errors.push({
          field: `tags[${index}]`,
          message: 'Tag cannot be empty',
          severity: ValidationSeverity.ERROR,
          code: 'EMPTY_TAG',
        })
        return tag
      }

      if (sanitizedTag.length > 50) {
        errors.push({
          field: `tags[${index}]`,
          message: 'Tag too long (maximum 50 characters)',
          severity: ValidationSeverity.ERROR,
          code: 'TAG_TOO_LONG',
        })
      }

      // Check for forbidden characters
      if (!/^[a-z0-9_-]+$/.test(sanitizedTag)) {
        errors.push({
          field: `tags[${index}]`,
          message: 'Tag contains invalid characters (only lowercase, numbers, underscore, hyphen allowed)',
          severity: ValidationSeverity.ERROR,
          code: 'INVALID_TAG_CHARACTERS',
        })
      }

      return sanitizedTag
    })

    return {
      isValid: errors.length === 0,
      sanitizedValue: sanitizedTags,
      errors,
      warnings,
    }
  }

  /**
   * Detect potential PHI (Protected Health Information) in text
   */
  public static detectPHI(text: string): { detected: boolean; patterns: string[] } {
    const detectedPatterns: string[] = []

    for (const pattern of this.PHI_PATTERNS) {
      if (pattern.test(text)) {
        detectedPatterns.push(pattern.source)
      }
    }

    return {
      detected: detectedPatterns.length > 0,
      patterns: detectedPatterns,
    }
  }

  /**
   * Check if URL is potentially suspicious
   */
  private static isSuspiciousUrl(url: string): boolean {
    const suspiciousPatterns = [
      /bit\.ly|tinyurl|t\.co|goo\.gl/, // URL shorteners
      /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, // IP addresses
      /[a-z0-9-]+\.tk|\.ml|\.ga|\.cf/, // Suspicious TLDs
    ]

    return suspiciousPatterns.some(pattern => pattern.test(url))
  }

  /**
   * Mask sensitive content for logging
   */
  private static maskSensitiveContent(content: string): string {
    let masked = content

    // Mask potential SSNs
    masked = masked.replace(/\b\d{3}-\d{2}-\d{4}\b/g, 'XXX-XX-XXXX')
    
    // Mask potential credit cards
    masked = masked.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX-XXXX')
    
    // Truncate if too long
    if (masked.length > 200) {
      masked = masked.substring(0, 200) + '...[TRUNCATED]'
    }

    return masked
  }
}

/**
 * File Upload Security Validator
 */
export class FileUploadValidator {
  private static readonly ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
    'text/plain',
    'audio/mpeg',
    'audio/wav',
    'video/mp4',
    'video/webm',
  ]

  private static readonly DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
    '.jar', '.msi', '.dll', '.app', '.deb', '.rpm',
  ]

  /**
   * Validate uploaded file for security
   */
  public static async validateFile(
    file: {
      name: string
      size: number
      type: string
      buffer: Buffer
    },
    config: FileValidationConfig
  ): Promise<ValidationResult> {
    const errors: ValidationError[] = []
    const warnings: ValidationWarning[] = []

    // Validate file size
    if (file.size > config.maxFileSize) {
      errors.push({
        field: 'file.size',
        message: `File size ${file.size} exceeds maximum ${config.maxFileSize} bytes`,
        severity: ValidationSeverity.ERROR,
        code: 'FILE_TOO_LARGE',
      })
    }

    // Validate MIME type
    if (!config.allowedMimeTypes.includes(file.type)) {
      errors.push({
        field: 'file.type',
        message: `File type ${file.type} not allowed`,
        severity: ValidationSeverity.ERROR,
        code: 'INVALID_FILE_TYPE',
      })
    }

    // Check for dangerous file extensions
    const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    if (this.DANGEROUS_EXTENSIONS.includes(extension)) {
      errors.push({
        field: 'file.name',
        message: `Dangerous file extension ${extension} detected`,
        severity: ValidationSeverity.CRITICAL,
        code: 'DANGEROUS_FILE_EXTENSION',
      })
    }

    // Validate filename
    if (!/^[a-zA-Z0-9._-]+$/.test(file.name)) {
      warnings.push({
        field: 'file.name',
        message: 'Filename contains special characters',
        recommendation: 'Consider sanitizing filename',
      })
    }

    // Magic number validation (check actual file type vs declared MIME type)
    const magicNumberValidation = this.validateMagicNumber(file.buffer, file.type)
    if (!magicNumberValidation.isValid) {
      errors.push(...magicNumberValidation.errors)
    }

    // Virus scanning (if required)
    if (config.virusScanRequired) {
      const virusScanResult = await this.performVirusScan(file.buffer)
      if (!virusScanResult.clean) {
        errors.push({
          field: 'file.content',
          message: 'File failed virus scan',
          severity: ValidationSeverity.CRITICAL,
          code: 'VIRUS_DETECTED',
        })
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      metadata: {
        originalSize: file.size,
        sanitizedName: this.sanitizeFilename(file.name),
        validatedAt: new Date().toISOString(),
      },
    }
  }

  /**
   * Validate file magic number matches declared MIME type
   */
  private static validateMagicNumber(buffer: Buffer, declaredType: string): ValidationResult {
    const errors: ValidationError[] = []

    const magicNumbers: Record<string, Buffer[]> = {
      'image/jpeg': [Buffer.from([0xFF, 0xD8, 0xFF])],
      'image/png': [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
      'image/gif': [Buffer.from([0x47, 0x49, 0x46])],
      'application/pdf': [Buffer.from([0x25, 0x50, 0x44, 0x46])],
    }

    const expectedMagicNumbers = magicNumbers[declaredType]
    if (expectedMagicNumbers) {
      const matches = expectedMagicNumbers.some(magic => 
        buffer.subarray(0, magic.length).equals(magic)
      )

      if (!matches) {
        errors.push({
          field: 'file.content',
          message: 'File content does not match declared MIME type',
          severity: ValidationSeverity.CRITICAL,
          code: 'MIME_TYPE_MISMATCH',
        })
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings: [],
    }
  }

  /**
   * Perform virus scanning (placeholder for integration with AV service)
   */
  private static async performVirusScan(buffer: Buffer): Promise<{ clean: boolean; threats?: string[] }> {
    // This would integrate with a virus scanning service like ClamAV
    // For now, return clean for all files
    logger.info('Virus scan placeholder - would scan file buffer', { bufferSize: buffer.length })
    return { clean: true }
  }

  /**
   * Sanitize filename to remove dangerous characters
   */
  private static sanitizeFilename(filename: string): string {
    return filename
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .replace(/_{2,}/g, '_')
      .substring(0, 100) // Limit filename length
  }
}

/**
 * Security event logger for validation events
 */
export class ValidationSecurityLogger {
  /**
   * Log validation failure for security monitoring
   */
  public static logValidationFailure(
    userDid: string,
    validationResult: ValidationResult,
    context: {
      ipAddress?: string
      userAgent?: string
      operation: string
    }
  ): void {
    const criticalErrors = validationResult.errors.filter(
      error => error.severity === ValidationSeverity.CRITICAL
    )

    if (criticalErrors.length > 0) {
      logger.error('Critical validation failure detected', {
        userDid,
        operation: context.operation,
        criticalErrors: criticalErrors.map(err => ({
          field: err.field,
          code: err.code,
          message: err.message,
        })),
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        timestamp: new Date().toISOString(),
      })

      // In production, this would trigger security alerts
      this.triggerSecurityAlert(userDid, criticalErrors, context)
    }
  }

  /**
   * Trigger security alert for critical validation failures
   */
  private static triggerSecurityAlert(
    userDid: string,
    errors: ValidationError[],
    context: any
  ): void {
    // This would integrate with incident response system
    logger.warn('Security alert triggered for validation failure', {
      userDid,
      errorCodes: errors.map(e => e.code),
      context,
    })
  }
}