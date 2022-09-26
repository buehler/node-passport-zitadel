import axios from 'axios';
import { Request } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import { importPKCS8, SignJWT } from 'jose';
import { IntrospectionResponse, Issuer } from 'openid-client';
import { Strategy } from 'passport';
import { ParsedQs } from 'qs';
import NodeRSA = require('node-rsa');

type ZitadelJwtProfile = {
  type: 'application';
  keyId: string;
  key: string;
  appId: string;
  clientId: string;
};

type EndpointAuthoriztaion =
  | {
      type: 'basic';
      clientId: string;
      clientSecret: string;
    }
  | {
      type: 'jwt-profile';
      profile: ZitadelJwtProfile;
    };

export type ZitadelIntrospectionOptions = {
  authority: string;
  authorization: EndpointAuthoriztaion;
  discoveryEndpoint?: string;
};

export class ZitadelIntrospectionStrategy extends Strategy {
  name = 'zitadel-introspection';

  private introspect?: (token: string) => Promise<IntrospectionResponse>;
  private jwt = '';
  private lastCreated = 0;

  constructor(private readonly options: ZitadelIntrospectionOptions) {
    super();
  }

  private get clientId() {
    if (this.options.authorization.type === 'basic') {
      return this.options.authorization.clientId;
    }

    return this.options.authorization.profile.clientId;
  }

  async authenticate(req: Request<ParamsDictionary, unknown, unknown, ParsedQs, Record<string, any>>) {
    if (!req.headers?.authorization || req.headers?.authorization?.toLowerCase().startsWith('bearer ') === false) {
      this.fail({ message: 'No bearer token found in authorization header' });
      return;
    }

    this.introspect ??= await this.getIntrospecter();

    const token = req.headers.authorization.substring(7);

    try {
      const result = await this.introspect(token);
      if (!result.active) {
        this.fail({ message: 'Token is not active' });
        return;
      }

      this.success(result);
    } catch (e) {
      (this.error ?? console.error)(e);
    }
  }

  private async createPayload(token: string): Promise<Record<string, string>> {
    if (this.options.authorization.type === 'basic') {
      return { token };
    }

    // check if the last created time is older than 60 minutes, if so, create a new jwt.
    if (this.lastCreated < Date.now() - 60 * 60 * 1000) {
      const rsa = new NodeRSA(this.options.authorization.profile.key);
      const key = await importPKCS8(rsa.exportKey('pkcs8-private-pem'), 'RSA256');

      this.jwt = await new SignJWT({
        iss: this.clientId,
        sub: this.clientId,
        aud: this.options.authority,
      })
        .setIssuedAt()
        .setExpirationTime('1h')
        .setProtectedHeader({
          alg: 'RS256',
          kid: this.options.authorization.profile.keyId,
        })
        .sign(key);
      this.lastCreated = Date.now();
    }

    return {
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: this.jwt,
      token,
    };
  }

  private async getIntrospecter() {
    const issuer = await Issuer.discover(this.options.discoveryEndpoint ?? this.options.authority);
    const introspectionEndpoint = issuer.metadata['introspection_endpoint'] as string;

    return async (token: string) => {
      const payload = await this.createPayload(token);

      const response = await axios.post(introspectionEndpoint, new URLSearchParams(payload), {
        auth:
          this.options.authorization.type === 'basic'
            ? {
                username: this.options.authorization.clientId,
                password: this.options.authorization.clientSecret,
              }
            : undefined,
      });

      return response.data as IntrospectionResponse;
    };
  }
}
