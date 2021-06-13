import Auth from '../auth-auto-refresh/Auth';
export default function(ctx, inject) {
    const opt = <%= JSON.stringify(options) %>
    const auth = new Auth(ctx, opt);

    inject('auth', {
        state: auth.state
    });
}
