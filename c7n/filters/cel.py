import celpy
import datetime
import celpy

from c7n.filters import Filter
from c7n.exceptions import PolicyValidationError
from c7n.resources.ec2 import InstanceImageBase


class CELFilter(
    Filter,
):
    """Generic CEL filter using CELPY
    """

    def __init__(self, data, manager):
        super().__init__(data, manager)
        assert data["type"].lower() == "cel"
        self.expr = data["expr"]
        self.parser = None
        self.cel_env = None
        self.cel_ast = None

        # pull all valid resource values from default CEL
        self.decls = {
            "Resource": celpy.celtypes.MapType,
            "Now": celpy.celtypes.TimestampType
        }

        # update possible resource vals with Custodian value filter function names
        self.decls.update(celpy.c7nlib.DECLARATIONS)

    schema = {
        'type': 'object',
        'additionalProperties': False,
        'required': ['type'],
        'properties': {
            'type': {'enum': ['cel']},
            'expr': {'type': 'string'}
        }
    }
    schema_alias = True
    annotate = True
    required_keys = {'cel', 'expr'}

    def validate(self):
        for filter in self.manager.data["filters"]:
            if 'expr' not in filter:
                raise PolicyValidationError(
                    f"CEL filters can only be used with provided expressions in {self.manager.data}"
                )

        # create our CEL env to be used for evaluating/processing the CEL expressions
        # (use C7N_Interpreted_Runner to provide a runner class that also includes option
        # of providing a C7N filter as an argument for the Environment's runner_class var)
        self.cel_env = celpy.Environment(annotations=self.decls, runner_class=celpy.c7nlib.C7N_Interpreted_Runner)

        # Compile the policy-provided "expr" string to see if it's a valid CEL expr or if it raises syntax errors
        print(f"Data we are trying to send into celpy as the expression: {self.expr}\n")
        self.cel_ast = self.cel_env.compile(self.data["expr"])
        print(f"self.cel_ast retrieved after parsing the provided policy to cel: {self.cel_ast}")
        return self

    def process(self, resources, event=None, filter=Filter):
        # if event is None:
        #     return resources

        filtered_resources = []
        for resource in resources:
            # transforms updated AST with celpy functions including C7N additions
            cel_prgm = self.cel_env.program(self.cel_ast, functions=celpy.c7nlib.FUNCTIONS)
            cel_activation = {
                "Resource": celpy.json_to_cel(resource),
                "Now": celpy.celtypes.TimestampType(datetime.datetime.utcnow()),
            }

            # this uses the C7n_Interpreted_Runner and actually calls evaluate() to run the expr
            # against a resource to see if it is included or not by the expr's filters
            with celpy.c7nlib.C7NContext(filter=self):  # Extends all MixIn filters to make them accessible for celpy code
                cel_result = cel_prgm.evaluate(cel_activation, self)
                if cel_result:
                    filtered_resources.append(resource)

        print(f"\nRetrieved filtered resources {filtered_resources}")
        return filtered_resources

class InstanceImageMixin:
    """
    CELFilter Mixin class to provide InstanceImageBase to CEL
    """

    def get_instance_image(self, resource):
        """
        get_instance_image retrieves the image id from the provided resource
        :param resource:
        :return image:
        """
        # image_base = InstanceImageBase
        print(f"\nMaking call to get_instance_image in Mixin class...")
        image_base = InstanceImageBase()
        print(f"Created image_base object: {image_base}")
        image = image_base.get_instance_image(resource)
        # image = get_instance_image(resource)
        print(f"\nRetrieved image from Mixin class: {image}...")
        return image


# need to add back:
#
# # class InstanceImageMixin(InstanceImageBase):
# #     """
# #     CELFilter Mixin class to provide InstanceImageBase to CEL
# #     """
# #
# #     def get_instance_image(self, resource):
# #         """
# #         get_instance_image retrieves the image id from the provided resource
# #         :param resource:
# #         :return image:
# #         """
# #         # image_base = InstanceImageBase
# #         print(f"\nMaking call to get_instance_image in Mixin class...")
# #         image_base = InstanceImageBase()
# #         print(f"Created image_base object: {image_base}")
# #         image = image_base.get_instance_image(resource)
# #         # image = get_instance_image(resource)
# #         print(f"\nRetrieved image from Mixin class: {image}...")
# #         return image
#
# # class ScheduleParserMixin:
#     # from c7n.filters.offhours import ScheduleParser
#     # self.parser = ScheduleParser()




# # Copyright The Cloud Custodian Authors.
# # SPDX-License-Identifier: Apache-2.0
# """
# CEL Implementation for Resource Filtering Logic
# """
# import celpy
# from c7n.filters.core import Filter
# from c7n.filters.offhours import ScheduleParser
# from c7n.exceptions import PolicyValidationError
#
# # from c7n.resources.ec2 import InstanceImageBase
# # from c7n.resources.iam import CredentialReport
# # from c7n.resources.kms import ResourceKmsKeyAlias
# # from c7n.filters.related import RelatedResourceFilter
#
# import c7n.resources.ec2.InstanceImageBase
# # import c7n.filters.iamaccess.CrossAccountAccessFilter
# # import c7n.resources.secretsmanager.CrossAccountAccessFilter
# # import c7n.resources.sns.SNSCrossAccount
# # import c7n.resources.ami.ImageUnusedFilter
# # import c7n.resources.ebs.SnapshotUnusedFilter
# # import c7n.resources.iam.IamRoleUsage
# # import c7n.resources.vpc.SGUsage
# # import c7n.resources.shield
# # import c7n.resources.account.ShieldEnabled
#
# ###### Figure out if we want to import this OR import the filters directly that use this and make those extend this?
# ###### Does CELFilter need to extend the implementation-level filter i.e.) ec2.ImageAge filter?
# class InstanceImageMixin:
#     """
#     CELFilter Mixin class to provide InstanceImageBase to CEL
#     """
#     def get_instance_image(self, resource):
#         """
#         get_instance_image retrieves the image id from the provided resource
#         :param resource:
#         :return image:
#         """
#         # image_base = InstanceImageBase
#         image_base = c7n.resources.ec2.InstanceImageBase
#         image = image_base.get_instance_image(resource)
#         return image
#
#
# # # needs underlying class refactored to pass resource-specific RelatedIdsExpression
# # # class RelatedResourceFilterMixin:
# # #     """
# # #     CELFilter MixIn class to provide RelatedResourceFilter to CEL
# # #     """
# # #     def get_related_ids(self, resources):
# # #         related_resource_filter = RelatedResourceFilter()
# # #         return related_resource_filter.get_related_ids(resources)
# # #
# # #     def get_related(self):
# # #         pass
# #
# #
# # class CredentialReportMixin:
# #     """
# #     CELFilter Mixin class to provide CredentialReportMixin to CEL
# #     """
# #     def get_credential_report(self):
# #         """
# #         get_credential_report retrieves a report about the user's IAM credentials
# #         :return report:
# #         """
# #         credential_report = CredentialReport()
# #         report = credential_report.get_credential_report()
# #         return report
# #
# #
# # class ResourceKmsKeyAliasMixin:
# #     """
# #     CELFilter Mixin class to provide ResourceKmsKeyAlias to CEL
# #     """
# #     def get_matching_aliases(self, resources):
# #         """
# #         get_matching_aliases retrieves keys aliases for the provided resources
# #         :param resources:
# #         :return matched:
# #         """
# #         resource_kms_key = ResourceKmsKeyAlias
# #         matched = resource_kms_key.get_matching_aliases(resources)
# #         return matched
# #
# #
# # class CrossAccountAccessFilterMixin:
# #     """
# #     CELFilter Mixin class to provide CrossAccountAccessFilter to CEL
# #     """
# #     def get_accounts(self):
# #         """
# #         get_accounts retrieves list of whitelisted accounts
# #         for use by the CrossAccountAccess filter
# #         :return accounts:
# #         """
# #         cross_account_access = c7n.filters.iamaccess.CrossAccountAccessFilter
# #         accounts = cross_account_access.get_accounts()
# #         return accounts
# #
# #     def get_vpcs(self):
# #         """
# #         get_vpcs retrieves list of whitelisted VPCs
# #         for use by the CrossAccountAccess filter
# #         :return vpc:
# #         """
# #         cross_account_access = c7n.filters.iamaccess.CrossAccountAccessFilter
# #         vpc = cross_account_access.get_vpcs()
# #         return vpc
# #
# #     def get_vpces(self):
# #         """
# #         get_vpces retrieves list of whitelisted VPC endpoints
# #         for use by the CrossAccountAccess filter
# #         :return vpce:
# #         """
# #         cross_account_access = c7n.filters.iamaccess.CrossAccountAccessFilter
# #         vpce = cross_account_access.get_vpces()
# #         return vpce
# #
# #     def get_orgids(self):
# #         """
# #         get_orgids retrieves list of whitelisted org ids
# #         for use by the CrossAccountAccess filter
# #         :return org_ids:
# #         """
# #         cross_account_access = c7n.filters.iamaccess.CrossAccountAccessFilter
# #         org_ids = cross_account_access.get_orgids()
# #         return org_ids
# #
# #     def get_resource_policy(self, resource):
# #         """
# #         get_resource_policy retrieves the resource-based policy
# #         for the provided resource for use by the CrossAccountAccess filter
# #         :param resource:
# #         :return policy:
# #         """
# #         cross_account_access = c7n.resources.secretsmanager.CrossAccountAccessFilter
# #         policy = cross_account_access.get_resource_policy(resource)
# #         return policy
# #
# #
# # class SNSCrossAccountMixin:
# #     """
# #     CELFilter Mixin class to provide SNSCrossAccount resource to CEL
# #     """
# #     def get_endpoints(self):
# #         """
# #         get_endpoints retrieves the whitelisted endpoints
# #         for use by the SNSCrossAccount filter
# #         :return endpoints:
# #         """
# #         sns_cross_account = c7n.resources.sns.SNSCrossAccount
# #         endpoints = sns_cross_account.get_endpoints()
# #         return endpoints
# #
# #     def get_protocols(self):
# #         """
# #         get_protocols retrieves the allowed protocols
# #         for use by the SNSCrossAccount filter
# #         :return protocols:
# #         """
# #         sns_cross_account = c7n.resources.sns.SNSCrossAccount
# #         protocols = sns_cross_account.get_protocols()
# #         return protocols
# #
# #
# # class ImagesUnusedMixin:
# #     """
# #     CELFilter Mixin class to provide ImageUnusedFilter resource to CEL
# #     """
# #     def _pull_ec2_images(self):
# #         """
# #         _pull_ec2_images retrieves used/unused ec2 images
# #         :return images:
# #         """
# #         image_unused_filter = c7n.resources.ami.ImageUnusedFilter
# #         images = image_unused_filter._pull_ec2_images()
# #         return images
# #
# #     def _pull_asg_images(self):
# #         """
# #         _pull_asg_images retrieves used/unused images in ASG launch configurations
# #         :return images:
# #         """
# #         image_unused_filter = c7n.resources.ami.ImageUnusedFilter
# #         images = image_unused_filter._pull_asg_images()
# #         return images
# #
# #
# # class SnapshotUnusedMixin:
# #     """
# #     CELFilter Mixin class to provide SnapshotUnusedMixin filter to CEL
# #     """
# #     def _pull_asg_snapshots(self):
# #         """
# #         _pull_asg_snapshots retrieves used/unused snapshots from
# #         ASG launch configurations
# #         :return asg_snapshots:
# #         """
# #         snapshot_unused_filter = c7n.resources.ebs.SnapshotUnusedFilter
# #         asg_snapshots = snapshot_unused_filter._pull_asg_snapshots()
# #         return asg_snapshots
# #
# #     def _pull_ami_snapshots(self):
# #         """
# #         _pull_ami_snapshots retrieves used/unused snapshots of AMIs
# #         :return ami_snapshots:
# #         """
# #         snapshot_unused_filter = c7n.resources.ebs.SnapshotUnusedFilter
# #         ami_snapshots = snapshot_unused_filter._pull_ami_snapshots()
# #         return ami_snapshots
# #
# #
# # class IamRoleUsageMixin:
# #     """
# #     CELFilter Mixin class to provide IamRoleUsage filter to CEL
# #     """
# #     def service_role_usage(self):
# #         """
# #         service_role_usage retrieves IAM roles being used by
# #         Lambda functions & ECS Clusters, as well as IAM roles
# #         attached to instance profiles of EC2/ASG resources
# #         :return results:
# #         """
# #         iam_role_usage = c7n.resources.iam.IamRoleUsage
# #         results = iam_role_usage.service_role_usage()
# #         return results
# #
# #     def instance_profile_usage(self):
# #         """
# #         instance_profile_usage retrieves IamInstanceProfiles
# #         of EC2/ASG resources
# #         :return results:
# #         """
# #         iam_role_usage = c7n.resources.iam.IamRoleUsage
# #         results = iam_role_usage.instance_profile_usage()
# #         return results
# #
# #
# # class SGUsageMixin:
# #     """
# #     CELFilter Mixin class to provide SGUsage filter to CEL
# #     """
# #     def scan_groups(self, resource):
# #         """
# #         scan_groups retrieves a set of all security groups currently in use
# #         :param resource:
# #         :return used:
# #         """
# #         sg_usage = c7n.resources.vpc.SGUsage
# #         used = sg_usage.scan_groups()
# #         return used
# #
# #
# # class IsShieldProtectedMixin:
# #     """
# #     CELFilter Mixin class to provide get_type_protections function to CEL
# #     """
# #     def get_type_protections(self, client, model):
# #         """
# #         get_type_protections retrieves a list of the resources
# #         that are being protected by AWS Shield
# #         :param client:
# #         :param model:
# #         :return protections:
# #         """
# #         return c7n.resources.shield.get_type_protections(client, model)
#
#
# # #### follow up with steven on this
# # #### is this what it's supposed to be doing?
# # class ShieldEnabledMixin:
# #     """
# #     CELFilter Mixin class to provide ShieldEnabled filter to CEL
# #     """
# #     def account_shield_subscriptions(self, resource):
# #         """
# #         account_shield_subscriptions retrieves the resources in the account
# #         that have subscriptions to AWS Shield
# #         :param resource:
# #         :return results:
# #         """
# #         shield_enabled = c7n.resources.account.ShieldEnabled
# #         results = shield_enabled.process(resource)
# #         return results
#
#
# class CELFilter(
#     Filter,
#     InstanceImageMixin,
#     # RelatedResourceFilterMixin,
#     # CredentialReportMixin,
#     # ResourceKmsKeyAliasMixin,
#     # CrossAccountAccessFilterMixin,
#     # SNSCrossAccountMixin,
#     # ImagesUnusedMixin,
#     # SnapshotUnusedMixin,
#     # IamRoleUsageMixin,
#     # SGUsageMixin,
#     # IsShieldProtectedMixin,
#     # ShieldEnabledMixin,
# ):
#     """Generic CEL filter using CELPY
#     """
#     # expr = None
#
#     def __init__(self, data, manager):
#         # super(CELFilter, self).__init__(data, manager)
#         super().__init__(data, manager)
#         assert data["type"].lower() == "cel"
#         self.expr = data["expr"]
#         self.parser = ScheduleParser()
#         self.cel_env = None
#         self.cel_ast = None
#
#         # pull all valid resource values from default CEL
#         self.decls = {
#             "Resource": celpy.celtypes.MapType,
#             "Now": celpy.celtypes.TimestampType
#         }
#
#         # update possible resource vals with Custodian value filter function names
#         self.decls.update(celpy.c7nlib.DECLARATIONS)
#
#     schema = {
#         'type': 'object',
#         'additionalProperties': False,
#         'required': ['type'],
#         'properties': {
#             'type': {'enum': ['cel']},
#             'expr': {'type': 'string'}
#         }
#     }
#     schema_alias = True
#     annotate = True
#     required_keys = {'cel', 'expr'}
#
#     def validate(self):
#         if 'expr' not in self.manager.data:
#             raise PolicyValidationError(
#                 f"CEL filters can only be used with provided expressions in {self.manager.data}"
#             )
#
#         # create our CEL env to be used for evaluating/processing the CEL expressions
#         # (use C7N_Interpreted_Runner to provide a runner class that also includes option
#         # of providing a C7N filter as an argument for the Environment's runner_class var)
#         self.cel_env = celpy.Environment(annotations=self.decls, runner_class=celpy.c7nlib.C7N_Interpreted_Runner)
#
#         # Compile the policy-provided "expr" string to see if it's a valid CEL expr or if it raises syntax errors
#         print(f"Data we are trying to send into celpy as the expression: {self.expr}\n")
#         self.cel_ast = self.cel_env.compile(self.data["expr"])
#         return self
#
#     def process(self, resources, event=None, filter=Filter):
#         if event is None:
#             return resources
#
#         filtered_resources = []
#         for resource in resources:
#
#             # transforms updated AST with celpy functions including C7N additions
#             cel_prgm = self.cel_env.program(self.cel_ast, functions=celpy.c7nlib.FUNCTIONS)
#             cel_activation = {
#                 "Resource": celpy.json_to_cel(resource),
#                 "Now": celpy.celtypes.TimestampType(datetime.datetime.utcnow()),
#             }
#
#             # this uses the C7n_Interpreted_Runner and actually calls evaluate() to run the expr
#             # against a resource to see if it is included or not by the expr's filters
#             with celpy.c7nlib.C7NContext(filter=self):  # Extends all MixIn filters to make them accessible for celpy code
#                 cel_result = cel_prgm.evaluate(cel_activation)
#                 if cel_result:
#                     filtered_resources.append(resource)
#
#         print(f"\nRetrieved filtered resources {filtered_resources}")
#         return filtered_resources
#
#
#     # def get_instance_image(self):
#         # from InstanceImageMixin
#     # def get_related_ids():
#         # from RelatedResourceMixin
#     # def get_related():
#         # from RelatedResourceMixin
#     # def get_matching_aliases():
#     # def get_accounts():
#     # def get_vpcs():
#     # def get_vpces():
#     # def get_orgids():
#     # def get_endpoints():
#     # def get_protocols():
#     # def get_resource_policy():
#     # def _pull_ec2_images():
#     # def _pull_asg_images():
#     # def _pull_asg_snapshots():
#     # def _pull_ami_snapshots():
#     # def service_role_usage():
#     # def instance_profile_usage():
#     # def scan_groups():
#     # def get_type_protections():
#     # def manager.get_model():
#     # def account_shield_subscriptions():
#
#
#     # C7N.filter.client.get_key_policy() ?
#     # C7N.filter.client.describe_subscription_filters ?
#     # C7N.filter.client.describe_snapshot_attribute ?



# class InstanceImageMixin:
#     """
#     CELFilter Mixin class to provide InstanceImageBase to CEL
#     """
#
#     def get_instance_image(self, resource):
#         """
#         get_instance_image retrieves the image id from the provided resource
#         :param resource:
#         :return image:
#         """
#         from c7n.resources.ec2 import InstanceImageBase
#         # image_base = InstanceImageBase
#         print(f"\nMaking call to get_instance_image in Mixin class...")
#         image_base = InstanceImageBase()
#         print(f"Created image_base object: {image_base}")
#         image = image_base.get_instance_image(resource)
#         # image = get_instance_image(resource)
#         print(f"\nRetrieved image from Mixin class: {image}...")
#         return image

# class InstanceImageMixin(InstanceImageBase):
#     """
#     CELFilter Mixin class to provide InstanceImageBase to CEL
#     """
#
#     def get_instance_image(self, resource):
#         """
#         get_instance_image retrieves the image id from the provided resource
#         :param resource:
#         :return image:
#         """
#         # image_base = InstanceImageBase
#         print(f"\nMaking call to get_instance_image in Mixin class...")
#         image_base = InstanceImageBase()
#         print(f"Created image_base object: {image_base}")
#         image = image_base.get_instance_image(resource)
#         # image = get_instance_image(resource)
#         print(f"\nRetrieved image from Mixin class: {image}...")
#         return image

# class ScheduleParserMixin:
    # from c7n.filters.offhours import ScheduleParser
    # self.parser = ScheduleParser()



