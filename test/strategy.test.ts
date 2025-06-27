import { IntrospectionResponse } from 'openid-client';
import passport from 'passport';
import { ZitadelIntrospectionOptions, ZitadelIntrospectionStrategy } from '../src';

const basic: ZitadelIntrospectionOptions = {
  authority: 'https://zitadel-libraries-l8boqa.zitadel.cloud',
  authorization: {
    type: 'basic',
    clientId: '180663584030785793@passport_js_strategy',
    clientSecret: 'uQgWLVhrBq36DU36b44cs4E7oQR04nNngAPugtGstxkznURdDlb4i7Afa7vylkVi',
  },
};
const jwt: ZitadelIntrospectionOptions = {
  authority: 'https://zitadel-libraries-l8boqa.zitadel.cloud',
  authorization: {
    type: 'jwt-profile',
    profile: {
      type: 'application',
      keyId: '180666194112545025',
      key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAsssDRiLlzyIxPE2UnKWZh52qlkQTyuEnFMraXjB791nkqyUh\njoIVMsIChJ0GYKP2J0dnScge0U3JbeD95v46j4PCkTN0i9E1HZ+qkBPJ7LffhN+1\nE9NCj+M+rjCCRzL738K6jpHBoWokEoNtTPDIvEpfXOkRJCkY/WZ77yugTF1EAPak\nKVO16cK4FDFMPNgSGbWqUaIqV/LsAdOpn4hSwZFe6qVmyEPjh1Lh+iZOL0WVyeZb\nXPChe6534XMtHTotjWaZOnpfN1tih0oOPqf/8AVSbIzqBp2ndAX9SAWWvrHP1CHa\n41UDrl2WqpeHoWEF+G/G2Lxxhhwklt2r314KPwIDAQABAoIBAAikh6P8S9+XZ4ni\ntixcVO+ZT4W0BMDp4Vm/9I5ZCaULU2JyiQy6fQvXFQgUDxrc0ilT6kpGwjab7ADD\nv4JLB8moNN+P/TJFCqxD65rLWhd3S/bAWaB7tdv+wCjrb2DBtis63onFwfZrixLa\nB46QlSOE9Nco7QsycWLOcW8+TKFkTAwfdPzpSA4f4/+rgDJvFijJu+z4kFrs40w3\nuTo5Gcxjt9KyS1a2kJoB2tuntIEAkZCIdHFhqr/Pjq2DmdG7QzfKlWFEv4Ys+jF7\nFRNR6oRVYumovh1Ja3TrBgYlZgP5Vc0xmue1mOJrcUgrnYcnPmItTIkzvDib8pgS\nv5QxMwECgYEAySWPHtTTlAMdej4erFCY2MQPI4dWaRYjKYKQ7zkWrj5s4KINl9yJ\njIdq5GkrHNbYNWbln7c7YMPrKYCDp/EN5Ymm1tpEPwLzQxLSGHjPSeaXlb9r2o6D\nVsZhF72YApmMvhoG0GRAoij1zT7kdz2wGG6gLUuFFseLZEfJZ0gogBMCgYEA44zm\nI1xl31zz8EvFD0gaU9mJs4A8dLE57G2P3Sbm+WbmF5+x011aEm2bUIPYRVQjeN0F\ngKutztIU4gJeHpmpS6WK+k6VvQ8xyj8IPQNXl8tgON/nixpnLzJKzOFsmI83rFnU\nkYBU+rtb2e/UOD8agCvGpz+eWb8ywUbjz6qKSqUCgYAmf0DAFt2To3D912vJcPd/\n7S40j49zN2BtbmbM0jFMEfiGmZ1eZkARHE3R/2rX7yqcNeBWzBvaLkUQwV7xQop1\nVv4OeuG66ZajTLPXKTALJc33RBahUstCTV+ByrCQNtEgBR0uvzE7l/lLWfEh/TV5\nx5pycNS9Al3kSHT8hmvx7wKBgQCfMR58FJMsjaIXNVr6ku3gRWtBifBBjw8/6XJh\nPGsQhj1ov48vmLp/8/BZhrOR5Qgf8Th9SR4CeBSl/RQNgmDfDERLUxkMuAmUPT6t\nOJ5aEq0RfQtG1MTlTuDnrrlDjcZcLEg7NrW858Cdmlw0sWj/zCBhN2+3x7xhXQ/Z\nY6z2BQKBgQCi6SIrOv4iB8fnpL6l6zOyYDO6cyJSp2Cln8VogICQAPy+Ps1yq3vG\njSsuBZ72StPBX97cXO5plTXxw740bwafLGIx+QUlSlZ5yfu4Dyzoo200D3w+gSan\nYFf+g/eXsH7ZEok9S0kUojvzu5v6uC1YvkKe6h24B7CjxIQRwbPMXw==\n-----END RSA PRIVATE KEY-----\n',
      appId: '180666181378638081',
      clientId: '180666181378703617@passport_js_strategy',
    },
  },
};
const pat = 'HLna9R_d5VN8l3jufF3m51OeJlJ7lBPZLUOx68rMW8yzELcSu5FHdQsZVOlOtsWNc-oi778';

test('create strategy', () => {
  const strategy = new ZitadelIntrospectionStrategy(basic);

  expect(strategy).toBeDefined();
  expect(strategy).toBeInstanceOf(ZitadelIntrospectionStrategy);
  expect(strategy.name).toBe('zitadel-introspection');
});

test('fail without header object', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic);
  const authenticate = passport.authenticate(strategy, (err, user, info) => {
    try {
      expect(user).toBeFalsy();
      expect(info?.message).toContain('No bearer token');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({}, {}, () => {});
});

test('fail without authorization header', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic);
  const authenticate = passport.authenticate(strategy, (err, user, info) => {
    try {
      expect(user).toBeFalsy();
      expect(info?.message).toContain('No bearer token');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: {} }, {}, () => {});
});

test('fail without bearer header', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic);
  const authenticate = passport.authenticate(strategy, (err, user, info) => {
    try {
      expect(user).toBeFalsy();
      expect(info?.message).toContain('No bearer token');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: 'basic foo' } }, {}, () => {});
});

test('authenticate the user against basic auth API project', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic);
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeNull();
      expect(user.active).toBe(true);
      expect(user.sub).toBe('180665971512443137');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer ${pat}` } }, {}, () => {});
});

test('authenticate the user against JWT Profile API project', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(jwt);
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeFalsy();
      expect(user.active).toBe(true);
      expect(user.sub).toBe('180665971512443137');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer ${pat}` } }, {}, () => {});
});

test('fail with random access token on basic auth', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic);
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeFalsy();
      expect(user).toBe(false);
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer foobarbaz0123456789` } }, {}, () => {});
});

test('fail with random access token on JWT profile auth', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(jwt);
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeFalsy();
      expect(user).toBe(false);
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer foobarbaz0123456789` } }, {}, () => {});
});

test('verify function is called with payload and verified callback', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic, (payload, verified) => {
    expect(payload).toBeDefined();
    expect(verified).toBeDefined();
    verified(null, payload);
  });
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeNull();
      expect(user).toBeDefined();
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer ${pat}` } }, {}, () => {});
});

test('verify function can return an error', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic, (payload, verified) => {
    verified(new Error('Test error'));
  });
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeDefined();
      expect(err.message).toBe('Test error');
      expect(user).toBeFalsy();
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer ${pat}` } }, {}, () => {});
});

test('verify function can return a custom user object', (done) => {
  const strategy = new ZitadelIntrospectionStrategy(basic, (payload, verified) => {
    const customUser = { id: payload.sub, name: 'Custom User' };
    verified(null, customUser);
  });
  const authenticate = passport.authenticate(strategy, (err, user: IntrospectionResponse, info) => {
    try {
      expect(err).toBeNull();
      expect(user).toBeDefined();
      expect(user.id).toBe('180665971512443137');
      expect(user.name).toBe('Custom User');
      done();
    } catch (e) {
      done(e);
    }
  });

  authenticate({ headers: { authorization: `bearer ${pat}` } }, {}, () => {});
});
