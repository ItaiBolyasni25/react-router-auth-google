import { SetCookie, type SetCookieInit } from "@mjackson/headers";
/**
 * This class is used to store the state and code verifier for the OAuth2 flow.
 *
 * If the user is redirected to the authorization endpoint, we need to store the
 * state and code verifier in a cookie so we can check that the state matches
 * when the user is redirected back to the application.
 *
 * The problem is that the user can open multiple tabs, and we need to keep
 * track of the state and code verifier for each tab. This class helps us do
 * that.
 *
 * It's a simple class that stores the state in a Set and the code verifier in a
 * Map. The state is used as the key to the code verifier, so we can easily
 * retrieve it when needed. We also have a method to convert the store to a
 * string, so we can store it in a cookie.
 *
 * The class also has a static method to create a new instance from a Request
 * object, this is useful when we need to get the store from the cookie.
 */
export declare class StateStore {
    states: Set<string>;
    codeVerifiers: Map<string, string>;
    state: string | undefined;
    codeVerifier: string | undefined;
    constructor(params?: import("url").URLSearchParams);
    /**
     * Append a new state and code verifier to the store
     */
    set(state: string, verifier?: string): void;
    /**
     * Check if the store has the given state
     */
    has(state?: string): boolean;
    /**
     * Get the code verifier for the given state
     */
    get(state: string): string | undefined;
    /**
     * Convert the store to a string
     *
     * This is useful when we need to store the store in a cookie
     */
    toString(): string;
    toSetCookie(cookieName?: string, options?: Omit<SetCookieInit, "value">): SetCookie;
    /**
     * Create a new instance from a Request object by getting the store from a
     * cookie with the given name.
     */
    static fromRequest(request: Request, cookieName?: string): StateStore;
}
