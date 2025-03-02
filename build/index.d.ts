import type { SetCookieInit } from "@mjackson/headers";
import { Google, OAuth2Tokens } from "arctic";
import { Strategy } from "remix-auth/strategy";
export declare const GoogleStrategyScopeSeperator = " ";
export declare const GoogleStrategyDefaultScopes: string[];
export type GoogleOAuth2UserClaims = {
    iss: string;
    azp: string;
    aud: string;
    sub: string;
    email: string;
    email_verified: boolean;
    at_hash: string;
    name: string;
    picture: string;
    given_name: string;
    iat: number;
    exp: number;
};
type URLConstructor = ConstructorParameters<typeof URL>[0];
export declare class GoogleOAuth2Strategy<User> extends Strategy<User, GoogleOAuth2Strategy.VerifyOptions> {
    protected options: GoogleOAuth2Strategy.ConstructorOptions;
    name: string;
    protected client: Google;
    private readonly accessType;
    private readonly includeGrantedScopes;
    constructor(options: GoogleOAuth2Strategy.ConstructorOptions, verify: Strategy.VerifyFunction<User, GoogleOAuth2Strategy.VerifyOptions>);
    private get cookieName();
    private get cookieOptions();
    authenticate(request: Request): Promise<User>;
    protected validateAuthorizationCode(code: string, codeVerifier: string): Promise<OAuth2Tokens>;
    protected createAuthorizationURL(): {
        state: string;
        codeVerifier: string;
        url: URL;
    };
    protected authorizationParams(initialParams: URLSearchParams, request: Request): URLSearchParams;
    private parseScope;
}
export declare namespace GoogleOAuth2Strategy {
    interface ConstructorOptions {
        /**
         * The name of the cookie used to keep state and code verifier around.
         *
         * The OAuth2 flow requires generating a random state and code verifier, and
         * then checking that the state matches when the user is redirected back to
         * the application. This is done to prevent CSRF attacks.
         *
         * The state and code verifier are stored in a cookie, and this option
         * allows you to customize the name of that cookie if needed.
         * @default "oauth2"
         */
        cookie?: string | (Omit<SetCookieInit, "value"> & {
            name: string;
        });
        /**
         * This is the Client ID of your application, provided to you by the Identity
         * Provider you're using to authenticate users.
         */
        clientId: string;
        /**
         * This is the Client Secret of your application, provided to you by the
         * Identity Provider you're using to authenticate users.
         */
        clientSecret: string;
        /**
         * The URL of your application where the Identity Provider will redirect the
         * user after they've logged in or authorized your application.
         */
        redirectURI: URLConstructor;
        /**
         * The scopes you want to request from the Identity Provider, this is a list
         * of strings that represent the permissions you want to request from the
         * user.
         */
        scopes?: string[];
        /**
         * The access type to use when sending the authorization request.
         * @default "online"
         */
        accessType?: "online" | "offline";
        /**
         * Whether to include granted scopes in the authorization request.
         * @default false
         */
        includeGrantedScopes?: boolean;
        /**
         * The prompt to use when sending the authorization request.
         * @default "none"
         */
        prompt?: "none" | "consent" | "select_account";
        /**
         * The login hint to use when sending the authorization request.
         */
        loginHint?: string;
        /**
         * The hd to use when sending the authorization request.
         */
        hd?: string;
    }
    /**
     * This interface declares what the developer will receive from the strategy
     * to verify the user identity in their system.
     */
    interface VerifyOptions {
        request: Request;
        tokens: OAuth2Tokens;
        claims: GoogleOAuth2UserClaims;
    }
}
export {};
