import { Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { CfnUserPool, UserPool, UserPoolClient } from 'aws-cdk-lib/aws-cognito';
import { CfnPolicyStore } from 'aws-cdk-lib/aws-verifiedpermissions';
import { getResourceLogicalId } from './utils';
import { IdentitySource } from '../src/identity-source';
import { PolicyStore, ValidationSettingsMode } from '../src/policy-store';


describe('Identity Source creation', () => {

  test('Creating Identity Source with required properties', () => {
    // GIVEN
    const stack = new Stack(undefined, 'Stack');

    // WHEN
    const userPool = new UserPool(stack, 'UserPool');
    const policyStore = new PolicyStore(stack, 'PolicyStore', {
      validationSettings: {
        mode: ValidationSettingsMode.OFF,
      },
    });
    const policyStoreLogicalId = getResourceLogicalId(policyStore, CfnPolicyStore);
    new IdentitySource(stack, 'IdentitySource', {
      configuration: {
        cognitoUserPoolConfiguration: {
          userPool: userPool,
        },
      },
      policyStore: policyStore,
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::VerifiedPermissions::IdentitySource', {
      Configuration: {
        CognitoUserPoolConfiguration: {
          UserPoolArn: {
            'Fn::GetAtt': [
              getResourceLogicalId(userPool, CfnUserPool),
              'Arn',
            ],
          },
        },
      },
      PolicyStoreId: {
        'Fn::GetAtt': [policyStoreLogicalId, 'PolicyStoreId'],
      },
    });
  });

  test('Creating Identity Source with all properties', () => {
    // GIVEN
    const stack = new Stack(undefined, 'Stack');

    // WHEN
    const userPool = new UserPool(stack, 'UserPool');
    const policyStore = new PolicyStore(stack, 'PolicyStore', {
      validationSettings: {
        mode: ValidationSettingsMode.OFF,
      },
    });
    const cognitoGroupEntityType = 'test';
    const policyStoreLogicalId = getResourceLogicalId(policyStore, CfnPolicyStore);
    new IdentitySource(stack, 'IdentitySource', {
      configuration: {
        cognitoUserPoolConfiguration: {
          clientIds: [
            '&ExampleCogClientId;',
          ],
          userPool: userPool,
          groupConfiguration: {
            groupEntityType: cognitoGroupEntityType,
          },
        },
      },
      policyStore: policyStore,
      principalEntityType: 'PETEXAMPLEabcdefg111111',
    });

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::VerifiedPermissions::IdentitySource', {
      Configuration: {
        CognitoUserPoolConfiguration: {
          ClientIds: [
            '&ExampleCogClientId;',
          ],
          GroupConfiguration: {
            GroupEntityType: cognitoGroupEntityType,
          },
          UserPoolArn: {
            'Fn::GetAtt': [
              getResourceLogicalId(userPool, CfnUserPool),
              'Arn',
            ],
          },
        },
      },
      PolicyStoreId: {
        'Fn::GetAtt': [policyStoreLogicalId, 'PolicyStoreId'],
      },
      PrincipalEntityType: 'PETEXAMPLEabcdefg111111',
    });
  });
});

describe('Identity Source reference existing Identity Source', () => {

  test('Referencing existing Identity Source providing Identity Source identifier', () => {
    // GIVEN
    const stack = new Stack();

    // WHEN
    const identitySourceId = 'ArE4uRLVgxtSX1Bx56NRTY';
    const identitySource = IdentitySource.fromIdentitySourceId(stack, 'ImportedIdentitySource', identitySourceId);

    // THEN
    expect(identitySource.identitySourceId).toBe(identitySourceId);
  });

});

describe('User Pool Client addition', () => {
  test('Adding a User Pool Client', () => {
    // GIVEN
    const stack = new Stack(undefined, 'Stack');

    // WHEN
    const userPool = new UserPool(stack, 'UserPool');
    const userPoolClient = new UserPoolClient(stack, 'UserPoolClient', { userPool: userPool });
    const policyStore = new PolicyStore(stack, 'PolicyStore', {
      validationSettings: {
        mode: ValidationSettingsMode.OFF,
      },
    });
    const policyStoreLogicalId = getResourceLogicalId(policyStore, CfnPolicyStore);
    const identitySource = new IdentitySource(stack, 'IdentitySource', {
      configuration: {
        cognitoUserPoolConfiguration: {
          userPool: userPool,
        },
      },
      policyStore: policyStore,
    });

    identitySource.addUserPoolClient(userPoolClient);

    // THEN
    Template.fromStack(stack).hasResourceProperties('AWS::VerifiedPermissions::IdentitySource', {
      Configuration: {
        CognitoUserPoolConfiguration: {
          ClientIds: [
            Match.objectEquals({
              Ref: Match.stringLikeRegexp('UserPoolClient*'),
            }),
          ],
          UserPoolArn: {
            'Fn::GetAtt': [
              getResourceLogicalId(userPool, CfnUserPool),
              'Arn',
            ],
          },
        },
      },
      PolicyStoreId: {
        'Fn::GetAtt': [policyStoreLogicalId, 'PolicyStoreId'],
      },
    });
  });
});
