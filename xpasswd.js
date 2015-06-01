"use strict";

/**
 * Module dependencies.
 */

var crypto = require("crypto");

/**
 * Password version definitions.
 */

exports.definitions = {
  1: {
    digest: "sha256",
    iterations: 4096,
    keylen: 1024,
    version: 1
  }
};

/**
 * Copy properties from sources to target.
 *
 * @param {Object} target The target object.
 * @param {...Object} sources The source object.
 * @return {Object} The target object.
 * @private
 */

function extend (target /* ...sources */) {
  var source, key, i = 1;
  while (source = arguments[i++]) {
    for (key in source) target[key] = source[key];
  }
  return target;
};

/**
 * Pack a password into a string.
 *
 * @param {String} key The hashed password to pack.
 * @param {Object} options
 *   @param {String} options.salt
 *   @param {Integer} options.version
 * @return {String}
 * @private
 */

function pack (key, options) {
  return [
    "",
    options.version,
    options.salt,
    key
  ].join("$");
}

/**
 * Unpack a password from a string.
 *
 * @param {String} digest The packed password to unpack.
 * @return {Object}
 * @private
 */

function unpack (digest) {
  var parts = digest.split("$");
  return {
    version: ~~parts[1],
    salt: parts[2],
    key: parts[3]
  };
}

/**
 * Digest a password using PBKDF2.
 *
 * @param {String} secret
 * @param {Object} options
 *   @param {String} options.salt
 *   @param {Integer} [options.iterations]
 *   @param {Integer} [options.keylen]
 *   @param {String} [options.digest]
 * @return {Promise}
 * @private
 */

function _digest (secret, options) {
  return new Promise(function (resolve, reject) {
    crypto.pbkdf2(
      secret,
      options.salt,
      options.iterations,
      options.keylen,
      options.digest,
      function (err, key) {
        if (err) return reject(err);
        key = key.toString("base64").replace(/=+$/, "");
        resolve(key);
      });
  });
}

/**
 * Digest a password.
 *
 * @param {String} secret
 * @param {Object} options
 *   @param {String} options.salt
 *   @param {String} [options.digest]
 *   @param {Integer} [options.iterations]
 *   @param {Integer} [options.keylen]
 *   @param {Integer} [options.version]
 * @return {Promise} A promise resolving to a packed password digest.
 * @api public
 */

exports.digest = function digest (secret, options) {

  // set defaults
  var version = options && options.version || 1;
  options = extend({}, exports.definitions[version], options);

  // generate salt if not given
  if (!options.salt) options.salt = crypto.randomBytes(9).toString("base64");

  // calculate PBKDF2 key
  return _digest(secret, options).then(function (key) {
    return pack(key, options);
  });
}

/**
 * Validate a password.
 *
 * @param {String} secret The password to validate.
 * @param {String} digest The packed password against which to validate.
 * @return {Promise} A promise resolving to true if the password is valid.
 * @api public
 */

exports.validate = function validate (secret, digest) {

  // unpack digest
  var options = unpack(digest);

  // check version
  if (exports.definitions[options.version]) {
    extend(options, exports.definitions[options.version]);
  } else {
    return Promise.reject(new Error(`Invalid key version ${version}`));
  }

  // validate PBKDF2 key
  return _digest(secret, options).then(function (key) {
    return key == options.key;
  });
}
