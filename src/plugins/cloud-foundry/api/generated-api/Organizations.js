/* DO NOT EDIT: This code has been generated by the cf-dotnet-sdk-builder */

(function () {
  'use strict';

  angular
    .module('cloud-foundry.api')
    .factory('cloud-foundry.api.OrganizationsService', OrganizationsServiceFactory);

  function OrganizationsServiceFactory() {
    /* eslint-disable camelcase */
    function OrganizationsService($http) {

      this.AssociateAuditorWithOrganization = function (guid, auditor_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/auditors/" + auditor_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.AssociateAuditorWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/auditors";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

      this.AssociateBillingManagerWithOrganization = function (guid, billing_manager_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/billing_managers/" + billing_manager_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.AssociateBillingManagerWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/billing_managers";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

      this.AssociateManagerWithOrganization = function (guid, manager_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/managers/" + manager_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.AssociateManagerWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/managers";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

      this.AssociatePrivateDomainWithOrganization = function (guid, private_domain_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/private_domains/" + private_domain_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.AssociateUserWithOrganization = function (guid, user_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/users/" + user_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.AssociateUserWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/users";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

      this.CreateOrganization = function (value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations";
        config.method = 'POST';
        config.data = value;
        $http(config);
      };

      this.DeleteOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.DisassociateAuditorWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/auditors";
        config.method = 'DELETE';
        config.data = value;
        $http(config);
      };

      this.DisassociateBillingManagerWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/billing_managers";
        config.method = 'DELETE';
        config.data = value;
        $http(config);
      };

      this.DisassociateManagerWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/managers";
        config.method = 'DELETE';
        config.data = value;
        $http(config);
      };

      this.DisassociateUserWithOrganizationByUsername = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "v2/organizations/" + guid + "/users";
        config.method = 'DELETE';
        config.data = value;
        $http(config);
      };

      this.GetOrganizationSummary = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/summary";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllAuditorsForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/auditors";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllBillingManagersForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/billing_managers";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllDomainsForOrganizationDeprecated = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/domains";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllManagersForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/managers";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllOrganizations = function (params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllPrivateDomainsForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/private_domains";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllServicesForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/services";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllSpaceQuotaDefinitionsForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/space_quota_definitions";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllSpacesForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/spaces";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllUsersForOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/users";
        config.method = 'GET';
        $http(config);
      };

      this.RemoveAuditorFromOrganization = function (guid, auditor_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/auditors/" + auditor_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RemoveBillingManagerFromOrganization = function (guid, billing_manager_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/billing_managers/" + billing_manager_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RemoveManagerFromOrganization = function (guid, manager_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/managers/" + manager_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RemovePrivateDomainFromOrganization = function (guid, private_domain_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/private_domains/" + private_domain_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RemoveUserFromOrganization = function (guid, user_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/users/" + user_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RetrieveOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "";
        config.method = 'GET';
        $http(config);
      };

      this.RetrievingOrganizationInstanceUsage = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/instance_usage";
        config.method = 'GET';
        $http(config);
      };

      this.RetrievingOrganizationMemoryUsage = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/memory_usage";
        config.method = 'GET';
        $http(config);
      };

      this.RetrievingRolesOfAllUsersInOrganization = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "/user_roles";
        config.method = 'GET';
        $http(config);
      };

      this.UpdateOrganization = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/organizations/" + guid + "";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

    }

    return OrganizationsService;
    /* eslint-enable camelcase */
  }

})();
