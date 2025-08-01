import {
  AtprotoIdentityDidMethods,
  Did,
  DidDocument,
  DidService,
} from '@atproto/did'
import {
  OAuthAuthorizationServerMetadata,
  oauthIssuerIdentifierSchema,
} from '@atproto/oauth-types'
import {
  IdentityInfo,
  IdentityResolver,
  ResolveIdentityOptions,
} from '@atproto-labs/identity-resolver'
import {
  GetCachedOptions,
  OAuthAuthorizationServerMetadataResolver,
} from './oauth-authorization-server-metadata-resolver.js'
import { OAuthProtectedResourceMetadataResolver } from './oauth-protected-resource-metadata-resolver.js'
import { OAuthResolverError } from './oauth-resolver-error.js'

export type { GetCachedOptions }
export type ResolveOAuthOptions = GetCachedOptions & ResolveIdentityOptions

export class OAuthResolver {
  constructor(
    readonly identityResolver: IdentityResolver,
    readonly protectedResourceMetadataResolver: OAuthProtectedResourceMetadataResolver,
    readonly authorizationServerMetadataResolver: OAuthAuthorizationServerMetadataResolver,
  ) {}

  /**
   * @param input - A handle, DID, PDS URL or Entryway URL
   */
  public async resolve(
    input: string,
    options?: ResolveOAuthOptions,
  ): Promise<{
    identityInfo?: IdentityInfo
    metadata: OAuthAuthorizationServerMetadata
  }> {
    // Allow using an entryway, or PDS url, directly as login input (e.g.
    // when the user forgot their handle, or when the handle does not
    // resolve to a DID)
    return /^https?:\/\//.test(input)
      ? this.resolveFromService(input, options)
      : this.resolveFromIdentity(input, options)
  }

  /**
   * @note this method can be used to verify if a particular uri supports OAuth
   * based sign-in (for compatibility with legacy implementation).
   */
  public async resolveFromService(
    input: string,
    options?: ResolveOAuthOptions,
  ): Promise<{
    metadata: OAuthAuthorizationServerMetadata
  }> {
    try {
      // Assume first that input is a PDS URL (as required by ATPROTO)
      const metadata = await this.getResourceServerMetadata(input, options)
      return { metadata }
    } catch (err) {
      if (!options?.signal?.aborted && err instanceof OAuthResolverError) {
        try {
          // Fallback to trying to fetch as an issuer (Entryway)
          const result = oauthIssuerIdentifierSchema.safeParse(input)
          if (result.success) {
            const metadata = await this.getAuthorizationServerMetadata(
              result.data,
              options,
            )
            return { metadata }
          }
        } catch {
          // Fallback failed, throw original error
        }
      }

      throw err
    }
  }

  public async resolveFromIdentity(
    input: string,
    options?: ResolveOAuthOptions,
  ): Promise<{
    identityInfo: IdentityInfo
    metadata: OAuthAuthorizationServerMetadata
    pds: URL
  }> {
    const identityInfo = await this.resolveIdentity(input, options)

    options?.signal?.throwIfAborted()

    const pds = extractPdsUrl(identityInfo.didDoc)

    const metadata = await this.getResourceServerMetadata(pds, options)

    return { identityInfo, metadata, pds }
  }

  public async resolveIdentity(
    input: string,
    options?: ResolveIdentityOptions,
  ): Promise<IdentityInfo> {
    try {
      return await this.identityResolver.resolve(input, options)
    } catch (cause) {
      throw OAuthResolverError.from(
        cause,
        `Failed to resolve identity: ${input}`,
      )
    }
  }

  public async getAuthorizationServerMetadata(
    issuer: string,
    options?: GetCachedOptions,
  ): Promise<OAuthAuthorizationServerMetadata> {
    try {
      return await this.authorizationServerMetadataResolver.get(issuer, options)
    } catch (cause) {
      throw OAuthResolverError.from(
        cause,
        `Failed to resolve OAuth server metadata for issuer: ${issuer}`,
      )
    }
  }

  public async getResourceServerMetadata(
    pdsUrl: string | URL,
    options?: GetCachedOptions,
  ) {
    try {
      const rsMetadata = await this.protectedResourceMetadataResolver.get(
        pdsUrl,
        options,
      )

      // ATPROTO requires one, and only one, authorization server entry
      if (rsMetadata.authorization_servers?.length !== 1) {
        throw new OAuthResolverError(
          rsMetadata.authorization_servers?.length
            ? `Unable to determine authorization server for PDS: ${pdsUrl}`
            : `No authorization servers found for PDS: ${pdsUrl}`,
        )
      }

      const issuer = rsMetadata.authorization_servers![0]!

      options?.signal?.throwIfAborted()

      const asMetadata = await this.getAuthorizationServerMetadata(
        issuer,
        options,
      )

      // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-resource-metadata-05#section-4
      if (asMetadata.protected_resources) {
        if (!asMetadata.protected_resources.includes(rsMetadata.resource)) {
          throw new OAuthResolverError(
            `PDS "${pdsUrl}" not protected by issuer "${issuer}"`,
          )
        }
      }

      return asMetadata
    } catch (cause) {
      throw OAuthResolverError.from(
        cause,
        `Failed to resolve OAuth server metadata for resource: ${pdsUrl}`,
      )
    }
  }
}

function isAtprotoPersonalDataServerService<M extends string>(
  this: DidDocument<M>,
  s: DidService,
): s is {
  id: '#atproto_pds' | `${Did<M>}#atproto_pds`
  type: 'AtprotoPersonalDataServer'
  serviceEndpoint: string
} {
  return (
    typeof s.serviceEndpoint === 'string' &&
    s.type === 'AtprotoPersonalDataServer' &&
    (s.id.startsWith('#')
      ? s.id === '#atproto_pds'
      : s.id === `${this.id}#atproto_pds`)
  )
}

function extractPdsUrl(document: DidDocument<AtprotoIdentityDidMethods>): URL {
  const service = document.service?.find(
    isAtprotoPersonalDataServerService<AtprotoIdentityDidMethods>,
    document,
  )

  if (!service) {
    throw new OAuthResolverError(
      `Identity "${document.id}" does not have a PDS URL`,
    )
  }

  try {
    return new URL(service.serviceEndpoint)
  } catch (cause) {
    throw new OAuthResolverError(
      `Invalid PDS URL in DID document: ${service.serviceEndpoint}`,
      { cause },
    )
  }
}
