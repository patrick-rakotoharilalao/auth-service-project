export interface OAuthProfileInterface {
    provider: string,
    providerId: string,
    accessToken?: string,
    refreshToken?: string,
    expiresAt: Date
}