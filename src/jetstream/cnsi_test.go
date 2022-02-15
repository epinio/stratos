package main

import (
	"errors"
	"net/http"
	"testing"

	_ "github.com/satori/go.uuid"
)

func TestRegisterCFCluster(t *testing.T) {
	t.Parallel()

	mockV2Info := setupMockServer(t,
		msRoute("/v2/info"),
		msMethod("GET"),
		msStatus(http.StatusOK),
		msBody(jsonMust(mockV2InfoResponse)))

	defer mockV2Info.Close()

	req := setupMockReq("POST", "", map[string]string{
		"cnsi_name":           "Some fancy CF Cluster",
		"api_endpoint":        mockV2Info.URL,
		"skip_ssl_validation": "true",
		"cnsi_client_id":      mockClientId,
		"cnsi_client_secret":  mockClientSecret,
	})

	_, _, _, _, db, mock := setupHTTPTest(req)
	defer db.Close()

	if dberr := mock.ExpectationsWereMet(); dberr != nil {
		t.Errorf("There were unfulfilled expectations: %s", dberr)
	}
}

func TestListCNSIs(t *testing.T) {
	t.Skip("TODO: fix this test")
	t.Parallel()

	req := setupMockReq("GET", "", nil)

	_, _, ctx, pp, db, mock := setupHTTPTest(req)
	defer db.Close()

	err := pp.listCNSIs(ctx)
	if err != nil {
		t.Errorf("Unable to retriece list of registered CNSIs from /cnsis: %v", err)
	}

	if dberr := mock.ExpectationsWereMet(); dberr != nil {
		t.Errorf("There were unfulfilled expectations: %s", dberr)
	}
}

func TestListCNSIsWhenListFails(t *testing.T) {
	t.Parallel()

	req := setupMockReq("GET", "", nil)

	_, _, ctx, pp, db, mock := setupHTTPTest(req)
	defer db.Close()

	// Mock a database error
	mock.ExpectQuery(selectAnyFromCNSIs).
		WillReturnError(errors.New("Unknown Database Error"))

	err := pp.listCNSIs(ctx)

	if err == nil {
		t.Errorf("Should receive an error when unable to get a list of registered CNSIs from /cnsis: %v", err)
	}
}
