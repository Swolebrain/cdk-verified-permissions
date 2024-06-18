import { readFileSync } from 'fs';
import { Duration, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { RestApi, Resource, Method } from 'aws-cdk-lib/aws-apigateway';
import { AccountRecovery, Mfa, OAuthScope, UserPool, UserPoolClientIdentityProvider, UserPoolEmail } from 'aws-cdk-lib/aws-cognito';
import { ApiGatewayConnectedPolicyStore } from '../src/api-gateway-connected-policy-store';
import { ValidationSettingsMode } from '../src/policy-store';


function buildUserPool(stack: Stack): UserPool {
  const userPoolName = 'AVPUserPool';
  const cognitoUserPool = new UserPool(stack, userPoolName, {
    userPoolName,
    accountRecovery: AccountRecovery.EMAIL_ONLY,
    signInCaseSensitive: false,
    selfSignUpEnabled: true,
    deviceTracking: {
      challengeRequiredOnNewDevice: true,
      deviceOnlyRememberedOnUserPrompt: true,
    },
    enableSmsRole: false,
    email: UserPoolEmail.withCognito('nobody@amazon.com'),
    autoVerify: { email: false, phone: false },
    mfa: Mfa.OFF,
    passwordPolicy: {
      minLength: 6,
      requireLowercase: false,
      requireDigits: false,
      requireSymbols: false,
      requireUppercase: false,
      tempPasswordValidity: Duration.days(7),
    },
  });
  cognitoUserPool.addClient(
    `${userPoolName}-Client`,
    {
      accessTokenValidity: Duration.minutes(60),
      authFlows: {
        adminUserPassword: false,
        userPassword: true,
        userSrp: true,
      },
      enableTokenRevocation: true,
      generateSecret: true,
      idTokenValidity: Duration.minutes(60),
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: true,
        },
        scopes: [OAuthScope.OPENID],
        callbackUrls: ['https://localhost:3000'],
      },
      preventUserExistenceErrors: true,
      refreshTokenValidity: Duration.days(30),
      userPoolClientName: `${userPoolName}-Client`,
      supportedIdentityProviders: [
        UserPoolClientIdentityProvider.COGNITO,
      ],
    },
  );
  cognitoUserPool.addDomain('CognitoDomain', {
    cognitoDomain: {
      domainPrefix: 'hosted-ui-avp-auth',
    },
  });
  return cognitoUserPool;
}
describe('creation of ApiGatewayConnectedPolicyStore', () => {
  test('Creating an ApiGatewayConnectedPolicyStore without passing lambda yields the right schema and a working lambda authorizer', () => {
    const stack = new Stack(undefined, 'Stack');
    const restApi = new RestApi(stack, 'restApi', {
      deploy: false,
      restApiName: 'PodcastApp',
    });
    const podcastsResource = new Resource(stack, 'podcastsResource', {
      parent: restApi.root,
      pathPart: 'podcasts',
      defaultCorsPreflightOptions: {
        allowOrigins: ['*'],
        allowMethods: ['*'],
        allowHeaders: ['*'],
      },
    });
    const podcastsByIdResource = new Resource(stack, 'podcastsByIdResource', {
      parent: podcastsResource,
      pathPart: '{podcastId}',
      defaultCorsPreflightOptions: {
        allowOrigins: ['*'],
        allowMethods: ['*'],
        allowHeaders: ['*'],
      },
    });
    const artistResource = new Resource(stack, 'artistResource', {
      parent: restApi.root,
      pathPart: 'artists',
      defaultCorsPreflightOptions: {
        allowOrigins: ['*'],
        allowMethods: ['*'],
        allowHeaders: ['*'],
      },
    });
    const artistsByIdResource = new Resource(stack, 'artistsByIdResource', {
      parent: artistResource,
      pathPart: '{artistId}',
      defaultCorsPreflightOptions: {
        allowOrigins: ['*'],
        allowMethods: ['*'],
        allowHeaders: ['*'],
      },
    });

    for (const httpVerb of ['get', 'post', 'delete']) {
      new Method(stack, `podcastMethod${httpVerb}`, {
        httpMethod: httpVerb.toUpperCase(),
        resource: podcastsResource,
      });
      new Method(stack, `artistMethod${httpVerb}`, {
        httpMethod: httpVerb.toUpperCase(),
        resource: artistResource,
      });
    }
    new Method(stack, 'podcastbyIdMethodAny', {
      httpMethod: 'ANY',
      resource: podcastsByIdResource,
    });
    new Method(stack, 'artistbyIdMethodPatch', {
      httpMethod: 'PATCH',
      resource: artistsByIdResource,
    });
    new Method(stack, 'artistbyIdMethodDelete', {
      httpMethod: 'DELETE',
      resource: artistsByIdResource,
    });

    const userPool = buildUserPool(stack);

    const apiGwPolicyStore = new ApiGatewayConnectedPolicyStore(stack, 'apiGwPStore', {
      restApi,
      identitySourceType: 'cognito',
      userPool,
      tokenType: 'identityToken',
    });

    expect(apiGwPolicyStore.authorizerLambda).toBeDefined();

    // check stack has a policy store
    Template.fromStack(stack).hasResourceProperties(
      'AWS::VerifiedPermissions::PolicyStore',
      {
        ValidationSettings: {
          Mode: ValidationSettingsMode.STRICT,
        },
      },
    );
    const policyStoreResourcesInStack = Template.fromStack(stack).findResources('AWS::VerifiedPermissions::PolicyStore');

    expect(Object.keys(policyStoreResourcesInStack).length).toEqual(1);
    // expect(JSON.parse(policyStoresInStack[0].Schema)).toStrictEqual({
    //     CedarJson: readFileSync('test/apigw-schema.json', 'utf-8'),
    // });
    expect(apiGwPolicyStore.cedarSchema).toStrictEqual(
      JSON.parse(readFileSync('test/apigw-schema.json', 'utf-8').toString()),
    );

    const idSourcesInStack = Template.fromStack(stack).findResources('AWS::VerifiedPermissions::IdentitySource');
    expect(Object.keys(idSourcesInStack).length).toEqual(1);

  });
});
