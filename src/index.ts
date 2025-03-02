import type { SetCookieInit } from "@mjackson/headers";
import {
	CodeChallengeMethod,
	Google,
	OAuth2Client,
	OAuth2RequestError,
	OAuth2Tokens,
	decodeIdToken,
	generateCodeVerifier,
	generateState,
} from "arctic";
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

const debug = createDebug("GoogleOAuth2Strategy");

export class GoogleOAuth2Strategy<User> extends Strategy<
	User,
	GoogleOAuth2Strategy.VerifyOptions
> {
	name = "google-oauth2";

	protected client: Google;

	private readonly accessType: string;

	private readonly includeGrantedScopes: boolean;

	constructor(
		protected options: GoogleOAuth2Strategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, GoogleOAuth2Strategy.VerifyOptions>,
	) {
		super(verify);

		this.accessType = this.options.accessType ?? "online";
		this.includeGrantedScopes = this.options.includeGrantedScopes ?? false;

		this.client = new Google(
			options.clientId,
			options.clientSecret,
			options.redirectURI.toString(),
		);
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || "google-oauth2";
		}
		return this.options.cookie?.name ?? "google-oauth2";
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<User> {
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

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

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

		if (!code) throw new ReferenceError("Missing code in the URL");

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
			claims: claims as GoogleOAuth2UserClaims,
		});

		debug("User authenticated");
		return user;
	}

	protected validateAuthorizationCode(code: string, codeVerifier: string) {
		return this.client.validateAuthorizationCode(code, codeVerifier);
	}

	protected createAuthorizationURL() {
		let state = generateState();
		let codeVerifier = generateCodeVerifier();

		let url = this.client.createAuthorizationURL(
			state,
			codeVerifier,
			this.parseScope(this.options.scopes) ?? [],
		);

		return { state, codeVerifier, url };
	}

	protected authorizationParams(
		initialParams: URLSearchParams,
		request: Request,
	): URLSearchParams {
		const params = new URLSearchParams(initialParams);
		params.set("access_type", this.accessType);
		params.set("include_granted_scopes", String(this.includeGrantedScopes));
		if (this.options.prompt) {
			initialParams.set("prompt", this.options.prompt);
		}
		if (this.options.hd) {
			initialParams.set("hd", this.options.hd);
		}
		if (this.options.loginHint) {
			initialParams.set("login_hint", this.options.loginHint);
		}

		return params;
	}

	private parseScope(scope: GoogleOAuth2Strategy.ConstructorOptions["scopes"]) {
		if (!scope) {
			return GoogleStrategyDefaultScopes;
		}

		if (Array.isArray(scope)) {
			return scope;
		}

		return scope;
	}
}

export namespace GoogleOAuth2Strategy {
	export interface ConstructorOptions {
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
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

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
	export interface VerifyOptions {
		request: Request;
		tokens: OAuth2Tokens;
		claims: GoogleOAuth2UserClaims;
	}
}
