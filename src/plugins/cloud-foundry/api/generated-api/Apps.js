/* DO NOT EDIT: This code has been generated by the cf-dotnet-sdk-builder */

(function () {
  'use strict';

  angular
    .module('cloud-foundry.api')
    .factory('cloud-foundry.api.AppsService', AppsServiceFactory);

  function AppsServiceFactory() {
    /* eslint-disable camelcase */
    function AppsService($http) {

      this.AssociateRouteWithApp = function (guid, route_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/routes/" + route_guid + "";
        config.method = 'PUT';
        $http(config);
      };

      this.CopyAppBitsForApp = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/copy_bits";
        config.method = 'POST';
        config.data = value;
        $http(config);
      };

      this.CreateDockerAppExperimental = function (value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps";
        config.method = 'POST';
        config.data = value;
        $http(config);
      };

      this.CreateApp = function (value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps";
        config.method = 'POST';
        config.data = value;
        $http(config);
      };

      this.DeleteApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.DownloadsStagedDropletForApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/droplet/download";
        config.method = 'GET';
        $http(config);
      };

      this.GetAppSummary = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/summary";
        config.method = 'GET';
        $http(config);
      };

      this.GetDetailedStatsForStartedApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/stats";
        config.method = 'GET';
        $http(config);
      };

      this.GetEnvForApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/env";
        config.method = 'GET';
        $http(config);
      };

      this.GetInstanceInformationForStartedApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/instances";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllApps = function (params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllRoutesForApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/routes";
        config.method = 'GET';
        $http(config);
      };

      this.ListAllServiceBindingsForApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/service_bindings";
        config.method = 'GET';
        $http(config);
      };

      this.RemoveRouteFromApp = function (guid, route_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/routes/" + route_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RemoveServiceBindingFromApp = function (guid, service_binding_guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/service_bindings/" + service_binding_guid + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.RestageApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/restage";
        config.method = 'POST';
        $http(config);
      };

      this.RetrieveApp = function (guid, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "";
        config.method = 'GET';
        $http(config);
      };

      this.TerminateRunningAppInstanceAtGivenIndex = function (guid, index, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "/instances/" + index + "";
        config.method = 'DELETE';
        $http(config);
      };

      this.UpdateApp = function (guid, value, params) {
        var config = {};
        config.params = params;
        config.url = "/v2/apps/" + guid + "";
        config.method = 'PUT';
        config.data = value;
        $http(config);
      };

    }

    return AppsService;
    /* eslint-enable camelcase */
  }

})();
