import fs from 'fs';
import path from 'path';
import { RestApi, RequestAuthorizer, IdentitySource } from 'aws-cdk-lib/aws-apigateway';
import { UserPool } from 'aws-cdk-lib/aws-cognito';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { IdentitySource as AVPIdentitySource } from './identity-source';
import { PolicyStore, ValidationSettingsMode } from './policy-store';

interface ApiGatewayConnectedPolicyStoreProps {
  /**
   * An API Gateway Rest API built with the RestApi L2 construct
   */
  restApi: RestApi;
  /**
   * Pass this if you want to override the lambda authorizer we provide, perhaps
   * because you want custom logic or want a different language.
   *
   * @default a NodeJS20 lambda function, with source code in lambda-src/index.js. It
   * has the default lambda permissions plus a policy to call VerifiedPermissions:IsAuthorizedwithToken
   */
  authorizerLambda?: lambda.Function;
  /**
   * The type of identity source. Only Cognito is currently supported but once aws-cdk-lib consumes
   * the model updates related to the reinforce release of oidc IdentitySources, we will enable that.
   */
  identitySourceType: 'oidc'|'cognito';
  /**
   * A cognito user pool. Required if identitySourceType is set to `cognito`
   */
  userPool?: UserPool;
  /**
   * The name of the entity type that represents your principal type. This value affects the schema that
   * is generated, as well as the identity source that is created.
   *
   * @default 'User'
   */
  principalEntityTypeName?: string;
  /**
   * The name of the entity type that represents groups of principals. This value affects the schema that is
   * is generated, as well as the identity source that is created.
   *
   * @default 'UserGroup'
   */
  groupEntityTypeName?: string;
  /**
   * The token type that will be used when calling VerifiedPermissions:IsAuthorizedwithToken. Your client will
   * call API gateway and pass the token in the `Authorization` header, and the API Gateway authorizer will
   * relay it to Verified Permissions either as an identity token or an access token, depending on the value
   * that you specify here.
   */
  tokenType: 'identityToken'|'accessToken';
}

const ALLOWED_METHODS = ['get', 'post', 'put', 'patch', 'delete'];


function getCedarAction(principalEntityTypeName: string, resourceTypeName: string) {
  return {
    appliesTo: {
      principalTypes: [
        principalEntityTypeName,
      ],
      resourceTypes: [
        resourceTypeName,
      ],
      context: {
        attributes: {},
        type: 'Record',
      },
    },
  };
}

function getCedarNamespaceFromApiName(apiName: string) {
  // TODO: ensure valid Cedar schema namespace
  return apiName;
}

export class ApiGatewayConnectedPolicyStore extends Construct {
  private restApi: RestApi;
  readonly policyStore: PolicyStore;
  readonly cedarSchema: Record<string, any>;
  readonly authorizerLambda: lambda.Function;
  readonly authorizer: RequestAuthorizer;
  readonly identitySourceType: 'oidc'|'cognito';
  readonly userPool?: UserPool;
  readonly groupEntityTypeName: string;
  readonly principalEntityTypeName: string;
  readonly identitySource: AVPIdentitySource;
  readonly tokenType: 'identityToken'|'accessToken';

  constructor(scope: Construct, id: string, props: ApiGatewayConnectedPolicyStoreProps) {
    super(scope, id);
    this.restApi = props.restApi;
    if (props.identitySourceType === 'oidc') {
      throw new Error('Not implemented yet');
    }
    if (props.identitySourceType === 'cognito' && !props.userPool) {
      throw new Error('userPool is required when identitySourceType is cognito');
    }
    this.userPool = props.userPool;
    const apiName = this.restApi.restApiName;
    const namespace = getCedarNamespaceFromApiName(apiName);
    this.principalEntityTypeName = props.principalEntityTypeName || 'User';
    this.groupEntityTypeName = props.groupEntityTypeName || 'UserGroup';
    this.tokenType = props.tokenType;
    this.cedarSchema = this.buildSchema(namespace);
    this.identitySourceType = props.identitySourceType;
    this.policyStore = new PolicyStore(this, 'PolicyStore', {
      description: `Policy store for ${apiName} API`,
      validationSettings: {
        mode: ValidationSettingsMode.STRICT,
      },
      schema: {
        cedarJson: JSON.stringify(this.cedarSchema),
      },
    });
    if (props.authorizerLambda) {
      this.authorizerLambda = props.authorizerLambda;
    } else {
      this.authorizerLambda = new lambda.Function(this, 'AVPAuthorizerLambda', {
        runtime: lambda.Runtime.NODEJS_20_X,
        code: lambda.Code.fromInline(
          fs.readFileSync(path.join(__dirname, 'lambda-src', 'index.js')).toString(),
        ),
        handler: 'index.handler',
        functionName: `AVPAuthorizerLambda-${this.policyStore.policyStoreId}`,
        initialPolicy: [
          new PolicyStatement({
            effect: Effect.ALLOW,
            actions: [
              'verifiedpermissions:isAuthorizedWithToken',
            ],
            resources: ['*'],
          }),
        ],
        environment: {
          POLICY_STORE_ID: this.policyStore.policyStoreId,
          NAMESPACE: namespace,
          TOKEN_TYPE: this.tokenType,
        },
      });
      this.authorizerLambda;
    }
    this.authorizer = new RequestAuthorizer(this, 'AVPAuthorizer', {
      authorizerName: 'AVPAuthorizer',
      handler: this.authorizerLambda,
      identitySources: [
        IdentitySource.header('Authorization'),
        IdentitySource.context('httpMethod'),
        IdentitySource.context('path'),
      ],
    });
    this.authorizer._attachToApi(this.restApi);
    this.identitySource = this.createIdentitySource(namespace);

  }

  private createIdentitySource(namespace: string): AVPIdentitySource {
    if (this.identitySourceType === 'cognito') {
      return new AVPIdentitySource(this, 'CognitoIdentitySource', {
        policyStore: this.policyStore,
        principalEntityType: `${namespace}::${this.principalEntityTypeName}`,
        configuration: {
          cognitoUserPoolConfiguration: {
            userPool: this.userPool!,
            groupConfiguration: {
              groupEntityType: `${namespace}::${this.groupEntityTypeName}`,
            },
          },
        },
      });
    } else {
      throw new Error(
        `Unsupported identity source type: ${this.identitySourceType}`,
      );
    }
  }

  public buildSchema(schemaNamespace: string) {
    const methods = this.restApi.methods;
    const cedarSchema: Record<typeof schemaNamespace, Record<'actions'|'entityTypes', any>> = {
      [schemaNamespace]: {
        entityTypes: {
          [this.groupEntityTypeName]: {
            memberOfTypes: [],
            shape: {
              type: 'Record',
              attributes: {},
            },
          },
          [this.principalEntityTypeName]: {
            memberOfTypes: [this.groupEntityTypeName],
            shape: {
              type: 'Record',
              attributes: {},
            },
          },
          Application: {
            memberOfTypes: [],
            shape: {
              type: 'Record',
              attributes: {},
            },
          },
        },
        actions: {},
      },
    };
    // some interesting method properties: renderMethodResponses, renderRequestModels
    for (const methodConstruct of methods) {
      let httpVerbs: string[] = [];
      if (methodConstruct.httpMethod.toLowerCase() === 'any') {
        httpVerbs = ALLOWED_METHODS;
      } else if (!ALLOWED_METHODS.includes(methodConstruct.httpMethod.toLowerCase())) {
        continue;
      } else {
        httpVerbs = [methodConstruct.httpMethod.toLowerCase()];
      }
      const parentResourcePath = methodConstruct.resource.path;
      for (const httpVerb of httpVerbs) {
        const cedarActionId = `${httpVerb} ${parentResourcePath}`;
        cedarSchema[schemaNamespace].actions[cedarActionId] = getCedarAction(this.principalEntityTypeName, 'Application');
      }
    }
    return cedarSchema;
  }

}

