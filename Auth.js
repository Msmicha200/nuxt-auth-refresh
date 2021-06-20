const cookie = require('cookie');

import Vue from 'vue';
import jwt from 'jwt-decode';

export default class Auth {
    state = {};
    #ctx = {};
    options = {};
    #prefix = null;
    #isGlobalToken = false;
    checkRefreshInterval = null;
    #referenceState = {
        user: null,
        loggedIn: false,
        token: null,
        refreshToken: null,
        strategieName: null
    };

    constructor(ctx, options) {
        this.#ctx = ctx;
        this.options = options?.strategies;
        this.#prefix = options.prefix ? options.prefix : 'auth';
        this.#isGlobalToken = options.globalToken === true ? true : false; 
        this.checkRefreshInterval = isNaN(Number(options.checkRefreshInterval)) ?
            (60 * 1000) : (options.checkRefreshInterval * 1000);

        if (!this.options) {
            return Promise.reject('Please, provide strategies');
        }

        this.state = Object.assign({}, this.#referenceState);

        for (const option in options.strategies) {

            this.options[option].refresh = options.strategies[option]?.refresh === true ? true : false;
            this.options[option].userAutoFetch = options.strategies[option].userAutoFetch === true ? true : false;
            this.options[option].autoRefresh = options.strategies[option]?.autoRefresh ? true : false;
        }


        this.state = new Vue({
            data: this.state
        });

        this.init();
    }
    
    // Review
    // TODO:: Default value for accessTokenProperty 
    init() {
        const cookies = this.getCookies();

        for (const cookie_key in cookies) {
            const array = cookie_key.split('.');
            
            if (array.length === 3 && array[0] === this.#prefix) {
                const token = cookies[array.join('.')];

                if (this.isExpired(token)) {
                    
                }
                
                this.state[array[2]] = token;
                this.state.strategieName = array[1];
                this.state.loggedIn = true;
            }
        }
    }

    /**
     * @param  {String} scheme_name Strategie title to login with.
     * @param  {Object} data Object with data to login.
     * @returns {Promise} Promise object represents the result of request to login endpoint.
     */
    async loginWith(scheme_name, data = false) {
        if (!(scheme_name in this.options)) {
            return Promise.reject('Please provide correct strategie name');
        }

        if (!this.options[scheme_name].endpoints) {
            return Promise.reject(`Please provide endpoints for ${scheme_name} strategie`);
        }

        if (!data) {
            return Promise.reject('Please provide data to login with');
        }

        const endpoint = this.options[scheme_name].endpoints?.login;
        const refreshEndpoint = this.options[scheme_name].endpoints?.refresh;
        
        if (!endpoint) {
            return Promise.reject('Please provide correct login endpoint');
        }

        const result = await this.request({
            url: endpoint.url,
            method: endpoint.method || 'POST',
            data: data
        });

        if (!(endpoint.tokenProperty in result.data)) {
            return Promise.resolve(result);
        }

        if (this.isExpired(result.data[endpoint.tokenProperty])) {
            return Promise.reject('Received token is expired');
        }

        if (this.state.loggedIn) {
            this.logOut(false);
            console.log('logged out')
        }

        this.state.token = result.data[endpoint.tokenProperty];
        this.state.loggedIn = true;
        this.state.strategieName = scheme_name;
        this.setCookie(`${this.#prefix}.${scheme_name}.token`, result.data[endpoint.tokenProperty]);

        if (this.isRefreshable(scheme_name)) {
            if (!(refreshEndpoint.tokenProperty in result.data)) {
                return Promise.reject('Please provide correct refresh token property in response');
            }

            if (this.isExpired(result.data[refreshEndpoint.tokenProperty])) {
                return Promise.reject('Received refresh token is expired');
            }

            this.state.refreshToken = result.data[refreshEndpoint.tokenProperty];
            this.setCookie(`${this.#prefix}.${scheme_name}.refreshToken`, 
                result.data[refreshEndpoint.tokenProperty]);
        }

        const redirects = this.options[scheme_name]?.redirects;
        
        if (redirects) {
            if ('home' in redirects && redirects.home != false) {
                return this.#ctx.redirect(redirects.home);
            }
        }

        if (this.options[scheme_name].userAutoFetch === true) {
            this.fetchUser();
        }

        return Promise.resolve(result);
    }

    /**
     * @param {Boolean} [withRedirect=true] Pass false if want to logout user without redirects.
     * @returns {Boolean} Returns true if logout is successful or redirect if provided logout page.
     */
    logOut(withRedirect = true) {
        if (!this.state.loggedIn) {
            return Promise.reject('You are not logged in');
        }
        
        const scheme_name = this.state.strategieName;

        this.removeCookie(`${this.#prefix}.${scheme_name}.token`);

        if (this.isRefreshable(scheme_name)) {
            this.removeCookie(`${this.#prefix}.${scheme_name}.refreshToken`);
        }
        
        this.state = Object.assign({}, this.#referenceState);

        const redirects = this.options[scheme_name]?.redirects;

        if (redirects && withRedirect) {
            if ('logout' in redirects && redirects.logout != false) {
                return this.#ctx.redirect(redirects.logout);
            }
        }

        return true;
    }
    
    /**
     * @param  {String} key Title of cookie to remove.
     * @param  {Object} options Cookie options.
     */
    removeCookie(key, options) {
        options = {
            maxAge: -1
        }

        this.setCookie(key, void 0, options);
    }

    /**
     * @returns {Promise} Promise object represents the result of fetch user.
     */
    async fetchUser() {
        if (!this.state.loggedIn) {
            return Promise.reject('You are not logged in');
        }

        const user_endpoint = this.options[this.state.strategieName].endpoints?.user;
        
        if (!user_endpoint) {
            return Promise.reject('Please provide user endpoint');
        }

        if (!user_endpoint.url) {
            return Promise.reject('Please provide user endpoint url')
        }

        if (!user_endpoint.property) {
            return Promise.reject('Please provide user endpoint property');
        }

        const user = await this.request({
            url: user_endpoint.url,
            method: user_endpoint.method || 'GET'
        });

        if (!(user_endpoint.property in user.data)) {
            return Promise.resolve(user);
        }

        this.state.user = user.data[user_endpoint.property];

        return Promise.resolve(user);
    }

    async refreshToken() {
        if (!this.state.loggedIn) {
            return Promise.reject('You are not logged in');
        }

        const scheme_name = this.state.strategieName;
        
        if (!this.isRefreshable(scheme_name)) {
            return Promise.reject('Current strategie is not refreshable');
        }

        if (this.isExpired(this.state.refreshToken)) {
            return Promise.reject('Refresh token is expired');
        }

        if (!this.state.refreshToken) {
            return Promise.reject('Current strategie does not have refresh token.')
        }

        const refreshEndpoint = this.options[scheme_name].endpoints.refresh;
        
        const result = await this.request({
            url: refreshEndpoint.url,
            method: refreshEndpoint.method || 'POST'
        });

        if (!(refreshEndpoint.accessTokenProperty in result.data)) {
            return Promise.reject('Please provide new access token property in response');
        }

        if (this.isExpired(result.data[refreshEndpoint.accessTokenProperty])) {
            return Promise.reject('Received token is expired');
        }

        this.state.token = result.data[refreshEndpoint.accessTokenProperty];
        this.setCookie(`${this.#prefix}.${scheme_name}.token`, result.data[refreshEndpoint.accessTokenProperty]);

        return true;
    }

    /**
     * @param  {String} scheme_name Strategie title to check refresh possibility.
     * @returns {Boolean} Returns true if it is possible to refresh provided strategie.
     */
    isRefreshable(scheme_name) {
        if (!(scheme_name in this.options)) {
            return false;
        }

        if (this.options[scheme_name].refresh !== true) {
            return false;
        }

        if (!this.options[scheme_name].endpoints['refresh']) {
            return Promise.reject('Please provide refresh endpoint');
        }

        if (!this.options[scheme_name].endpoints.refresh.url) {
            return Promise.reject('Please provide refresh endpoint url');
        }

        if (!this.options[scheme_name].endpoints.refresh.tokenProperty) {
            return Promise.reject('Please provide refresh endpoint token property');
        }

        return true;
    }
    
    /**
     * @param  {String} token
     * @returns {Boolean} Returns true if provided token is expired.
     */
    isExpired(token) {
        const token_obj = jwt(token);
        
        if ('exp' in token_obj) {
            return Date.now() > token_obj.exp * 1000;
        }
        else {
            return Promise.reject('Please provide expiration date in token payload');
        }
    }

    /**
     * @param  {String} key Title of cookie to set.
     * @param  {String} value Cookie value to set.
     * @param  {Object} options Cookie options.
     */
    setCookie(key, value, options = {}) {
        if (value == false) {
            options.maxAge = -1;
        }

        const serialized_cookie = cookie.serialize(key, value, options);
        
        if (process.client) {
            document.cookie = serialized_cookie;
        }
        else if (process.server && this.#ctx.res) {
            const cookies = this.#ctx.res.getHeader('Set-Cookie') || [];

            cookies.unshift(serialized_cookie);

            this.#ctx.res.setHeader('Set-Cookie', serialized_cookie);
            // this.#ctx.res.setHeader('Set-Cookie', cookies.filter((elem, idx, arr) =>
                // arr.findIndex(val => val.startsWith(elem.substr(0, elem.indexOf('=')))) === idx));
        }
        else {
            return Promise.reject('Can not set cookie');
        }
    }

    /**
     * @returns {Object} Returns all cookies.
     */
    getCookies() {
        const cookie_str = process.client ? document.cookie : this.#ctx.req.headers.cookie;

        return cookie.parse(cookie_str || '');
    }

    /**
     * @param {Object} options Config of request to send.
     * @param {String} options.url Endpoint to request.
     * @param {String} options.method Method to request.
     * @param {Object} options.data Request body.
     * @returns {Promise} Promise object represents response of sended request.
     */
    request(options) {
        const url = options.url || false;
        const method = options.method || false;
        const data = options.data || false;
        const config = {
            method: method,
            url: url
        };

        if (data) {
            config.data = data;
        }

        if (method && url) {
            return this.#ctx.app.$axios(config);
        }
        else {
            return Promise.resolve(false);
        }
    }
}
