# `xpasswd` - a library for digesting and validating passwords

`xpasswd` implements a versioned password digest scheme similar to the UNIX
passwd file. The default digest version configurations are defined in the
`xpasswd.definitions` object. You may safely override this object with your 
own definitions.

# Usage

```js
import {digest, validate} from "./xpasswd";

// digest "xyzzy" and log the result from the returned Promise
digest("xyzzy").then(function (key) {
  console.log(key);
  // use Promise chaining to validate the password
  return validate("xyzzy", key);
}).then(function (success) {
  console.log("validation succeeded:" success);
});
```

# License

MIT
