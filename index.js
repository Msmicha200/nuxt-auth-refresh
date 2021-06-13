const path = require('path');

const auth_module = function (module_options) {
    const options = false ? module_options : this.options.auth;
    this.addPlugin({
        src: path.resolve(__dirname, 'plugin.js'),
        options
    });
}

module.exports = auth_module;
