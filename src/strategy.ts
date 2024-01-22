import axios from 'axios';
import { Request } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import { importPKCS8, SignJWT } from 'jose';
import NodeRSA from 'node-rsa';
import { IntrospectionResponse, Issuer } from 'openid-client';
import { Strategy } from 'passport';
import { ParsedQs } from 'qs';

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
  introspectionEndpoint?: string;
  issuer?: Issuer;
};

export class ZitadelIntrospectionStrategy extends Strategy {
  name = 'zitadel-introspection';

  private issuer: Issuer | undefined;
  private introspectionEndpoint: string;
  private introspect?: (token: string) => Promise<IntrospectionResponse>;

  constructor(private readonly options: ZitadelIntrospectionOptions) {
    super();
    this.issuer = options.issuer;
    this.introspectionEndpoint = options.introspectionEndpoint || '';
  }

  public static async create(options: ZitadelIntrospectionOptions): Promise<ZitadelIntrospectionStrategy> {
    const issuer = await Issuer.discover(options.discoveryEndpoint ?? options.authority);
    options.issuer = issuer;
    const strategy = new ZitadelIntrospectionStrategy(options);

    return strategy;
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

  private async getIntrospecter() {
    if (!this.introspectionEndpoint) {
      if (!this.issuer) {
        this.issuer = await Issuer.discover(this.options.discoveryEndpoint ?? this.options.authority);
      }
      this.introspectionEndpoint = this.issuer.metadata['introspection_endpoint'] as string;
    }

    let jwt = '';
    let lastCreated = 0;

    const getPayload = async (token: string): Promise<Record<string, string>> => {
      if (this.options.authorization.type === 'basic') {
        return { token };
      }

      // check if the last created time is older than 60 minutes, if so, create a new jwt.
      if (lastCreated < Date.now() - 60 * 60 * 1000) {
        const rsa = new NodeRSA(this.options.authorization.profile.key);
        const key = await importPKCS8(rsa.exportKey('pkcs8-private-pem'), 'RSA256');

        jwt = await new SignJWT({
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
        lastCreated = Date.now();
      }

      return {
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: jwt,
        token,
      };
    };

    return async (token: string) => {
      const payload = await getPayload(token);

      const response = await axios.post(this.introspectionEndpoint, new URLSearchParams(payload), {
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
