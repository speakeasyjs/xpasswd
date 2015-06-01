"use strict";

var assert = require("assert");
var xpasswd = require("./xpasswd");

describe("xpasswd", function () {
  this.slow(500);

  it("should digest a password with default options", function () {
    return xpasswd.digest("xyzzy").then(function (subject) {
      assert(this.subject = subject);
    }.bind(this));
  });

  it("should validate a password", function () {
    return xpasswd.validate("xyzzy", this.subject).then(function (success) {
      assert(success);
    });
  });

});
