import { CodeChallengeMethod, Google, OAuth2Client, OAuth2RequestError, OAuth2Tokens, decodeIdToken, generateCodeVerifier, generateState, } from "arctic";
import createDebug from "debug";
import { redirect } from "react-router";
import { Strategy } from "remix-auth/strategy";
import { StateStore } from "./lib/store.js";
export const GoogleStrategyScopeSeperator = " ";
export const GoogleStrategyDefaultScopes = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
];
export { OAuth2RequestError, CodeChallengeMethod };
const debug = createDebug("GoogleOAuth2Strategy");
export class GoogleOAuth2Strategy extends Strategy {
    options;
    name = "google-oauth2";
    client;
    accessType;
    includeGrantedScopes;
    constructor(options, verify) {
        super(verify);
        this.options = options;
        this.accessType = this.options.accessType ?? "online";
        this.includeGrantedScopes = this.options.includeGrantedScopes ?? false;
        this.client = new Google(options.clientId, options.clientSecret, options.redirectURI.toString());
    }
    get cookieName() {
        if (typeof this.options.cookie === "string") {
            return this.options.cookie || "google-oauth2";
        }
        return this.options.cookie?.name ?? "google-oauth2";
    }
    get cookieOptions() {
        if (typeof this.options.cookie !== "object")
            return {};
        return this.options.cookie ?? {};
    }
    async revokeToken(token) {
        await this.client.revokeToken(token);
    }
    async authenticate(request) {
        debug("Request URL", request.url);
        let url = new URL(request.url);
        let stateUrl = url.searchParams.get("state");
        let error = url.searchParams.get("error");
        if (error) {
            let description = url.searchParams.get("error_description");
            let uri = url.searchParams.get("error_uri");
            throw new OAuth2RequestError(error, description, uri, stateUrl);
        }
        if (!stateUrl) {
            debug("No state found in the URL, redirecting to authorization endpoint");
            let { state, codeVerifier, url } = this.createAuthorizationURL();
            debug("State", state);
            debug("Code verifier", codeVerifier);
            url.search = this.authorizationParams(url.searchParams, request).toString();
            debug("Authorization URL", url.toString());
            let store = StateStore.fromRequest(request, this.cookieName);
            store.set(state, codeVerifier);
            throw redirect(url.toString(), {
                headers: {
                    "Set-Cookie": store
                        .toSetCookie(this.cookieName, this.cookieOptions)
                        .toString(),
                },
            });
        }
        let code = url.searchParams.get("code");
        if (!code)
            throw new ReferenceError("Missing code in the URL");
        let store = StateStore.fromRequest(request, this.cookieName);
        if (!store.has()) {
            throw new ReferenceError("Missing state on cookie.");
        }
        if (!store.has(stateUrl)) {
            throw new RangeError("State in URL doesn't match state in cookie.");
        }
        let codeVerifier = store.get(stateUrl);
        if (!codeVerifier) {
            throw new ReferenceError("Missing code verifier on cookie.");
        }
        debug("Validating authorization code");
        let tokens = await this.validateAuthorizationCode(code, codeVerifier);
        debug("Verifying the user profile");
        const idToken = tokens.idToken();
        const claims = decodeIdToken(idToken);
        let user = await this.verify({
            request,
            tokens,
            claims: claims,
        });
        debug("User authenticated");
        return user;
    }
    validateAuthorizationCode(code, codeVerifier) {
        return this.client.validateAuthorizationCode(code, codeVerifier);
    }
    createAuthorizationURL() {
        let state = generateState();
        let codeVerifier = generateCodeVerifier();
        let url = this.client.createAuthorizationURL(state, codeVerifier, this.parseScope(this.options.scopes) ?? []);
        return { state, codeVerifier, url };
    }
    authorizationParams(initialParams, request) {
        const params = new URLSearchParams(initialParams);
        params.set("access_type", this.accessType);
        params.set("include_granted_scopes", String(this.includeGrantedScopes));
        if (this.options.prompt) {
            params.set("prompt", this.options.prompt);
        }
        if (this.options.hd) {
            params.set("hd", this.options.hd);
        }
        if (this.options.loginHint) {
            params.set("login_hint", this.options.loginHint);
        }
        return params;
    }
    parseScope(scope) {
        if (!scope) {
            return GoogleStrategyDefaultScopes;
        }
        if (Array.isArray(scope)) {
            return scope;
        }
        return scope;
    }
}
//# sourceMappingURL=index.js.map