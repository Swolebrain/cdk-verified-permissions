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
  restApi: RestApi;
  authorizerLambda?: lambda.Function;
  identitySourceType: 'oidc'|'cognito';
  userPool: UserPool;
  groupEntityTypeName?: string;
  principalEntityTypeName?: string;
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
  readonly userPool: UserPool;
  readonly groupEntityTypeName: string;
  readonly principalEntityTypeName: string;
  readonly identitySource: AVPIdentitySource;
  readonly tokenType: 'identityToken'|'accessToken';

  constructor(scope: Construct, id: string, props: ApiGatewayConnectedPolicyStoreProps) {
    super(scope, id);
    this.restApi = props.restApi;
    const apiName = this.restApi.restApiName;
    const namespace = getCedarNamespaceFromApiName(apiName);
    this.principalEntityTypeName = `${namespace}::${props.principalEntityTypeName || 'User'}`;
    this.groupEntityTypeName = `${namespace}::${props.groupEntityTypeName || 'UserGroup'}`;
    this.userPool = props.userPool;
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
    this.identitySource = this.createIdentitySource();

  }

  private createIdentitySource(): AVPIdentitySource {
    if (this.identitySourceType === 'cognito') {
      return new AVPIdentitySource(this, 'CognitoIdentitySource', {
        policyStore: this.policyStore,
        principalEntityType: this.principalEntityTypeName,
        configuration: {
          cognitoUserPoolConfiguration: {
            userPool: this.userPool,
            groupConfiguration: {
              groupEntityType: this.groupEntityTypeName,
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

