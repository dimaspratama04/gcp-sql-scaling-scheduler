package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/joho/godotenv"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
)

type SQLInstancesData struct {
	Name            string `json:"name"`
	DatabaseVersion string `json:"database_version"`
	Region          string `json:"region"`
	State           string `json:"state"`
	Tier            string `json:"tier"`
}

type TemplateSuccessResponse struct {
	StatusCode int              `json:"status_code"`
	StatusText string           `json:"status_text"`
	Message    string           `json:"message"`
	Timestamp  string           `json:"timestamp"`
	Data       SQLInstancesData `json:"data"`
}

type TemplateErrorResponse struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type ErrorJSON struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type RequestPayload struct {
	Tier         string            `json:"tier"`
	InstanceName string            `json:"instance_name"`
	Flags        map[string]string `json:"flags"`
}

var (
	projectID string
	port      string
)

var allowedKeys = map[string]bool{
	"tier":          true,
	"instance_name": true,
	"flags":         true,
}

func init() {
	godotenv.Load(".env")
	if os.Getenv("ENV") == "local" {
		err := godotenv.Load(".env")
		if err != nil {
			log.Print("Error loading .env file")
		}
	}

	projectID = os.Getenv("PROJECT_ID")
	port = os.Getenv("PORT")

	if port == "" {
		port = "80"
	}
}

func main() {
	http.HandleFunc("/check", checkInstancesHandler)
	http.HandleFunc("/action", actionHandler)

	fmt.Println("Server running at http://localhost:" + port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func newSqlService() (*sqladmin.Service, error) {
	ctx := context.Background()
	sqlService, err := sqladmin.NewService(ctx, option.WithCredentialsFile("service_account.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to find Service Account: %w", err)
	}
	return sqlService, nil
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed.", "")
		return
	}

	do := r.URL.Query().Get("do")

	if do != "update" {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid Request", "")
		return
	}

	// key of body valiadtion, only allowed key will proceed
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", err)
		return
	}

	for key := range raw {
		if !allowedKeys[key] {
			writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid key: %s", key), "")
			return
		}
	}

	// decode to struct
	jsonBody, _ := json.Marshal(raw)
	var req RequestPayload
	if err := json.Unmarshal(jsonBody, &req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to parse request body", err)
		return
	}

	// null request validation
	if req.Tier == "" || req.InstanceName == "" {
		writeErrorResponse(w, http.StatusBadRequest, "tier and instance_name are required", "")
		return
	}

	// tier format request validation
	var validTierFormat = regexp.MustCompile(`^db-custom-[1-9][0-9]*-[1-9][0-9]*$`)
	if !validTierFormat.MatchString(req.Tier) {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid tier format. Only db-custom-<cpus>-<memory> allowed", "")
		return
	}

	// create sqlservice api
	sqlService, err := newSqlService()
	if err != nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Service Account not found.", err)
		return
	}

	// check instances validation
	_, err = checkStatusInstances(sqlService, projectID, req.InstanceName)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed get Instances.", "Check name of Instance and make sure the service account have Cloud SQL Admin permission")
		return
	}

	var dbFlags []*sqladmin.DatabaseFlags
	for name, value := range req.Flags {
		dbFlags = append(dbFlags, &sqladmin.DatabaseFlags{
			Name:  name,
			Value: value,
		})
	}

	err = doUpdateSpesification(sqlService, req.InstanceName, req.Tier, dbFlags)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Update Instances failed", err)
		return
	}
	writeSuccessResponse(w, http.StatusOK, "Instances succesfully updated, for detail check your console.", "")
}

func doUpdateSpesification(sqlService *sqladmin.Service, instanceName string, tier string, flags []*sqladmin.DatabaseFlags) error {
	// prepare execute to database
	patchReq := &sqladmin.DatabaseInstance{
		Settings: &sqladmin.Settings{
			Tier:          tier,
			DatabaseFlags: flags,
		},
	}

	// execute
	_, err := sqlService.Instances.Patch(projectID, instanceName, patchReq).Do()
	if err != nil {
		return fmt.Errorf("failed to update instance: %v", err)
	}

	return nil
}

func checkInstancesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed.", "")
		return
	}

	sqlService, err := newSqlService()
	if err != nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Service Account not found.", err)
		return
	}

	instancesListCall := sqlService.Instances.List(projectID)
	instancesList, err := instancesListCall.Do()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to list instances.", "Check name of Instance and make sure the service account have Cloud SQL Admin permission ")
		return
	}

	var dataListInstances []SQLInstancesData
	for _, instance := range instancesList.Items {
		dataListInstances = append(dataListInstances, SQLInstancesData{
			Name:            instance.Name,
			DatabaseVersion: instance.DatabaseVersion,
			Region:          instance.Region,
			State:           instance.State,
			Tier:            instance.Settings.Tier,
		})
	}

	writeSuccessResponse(w, http.StatusOK, "Successfully fetched all instances.", dataListInstances)
}

func writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	response := map[string]interface{}{
		"data":        data,
		"status_code": statusCode,
		"status_text": http.StatusText(statusCode),
		"message":     message,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err interface{}) {
	var errorType string
	var errorDescription string

	switch e := err.(type) {
	case *googleapi.Error:
		errorType = fmt.Sprintf("googleapi_%d", e.Code)
		errorDescription = e.Message
	case error:
		errorType = "internal_error"
		errorDescription = e.Error()
	case string:
		errorType = "client_error"
		errorDescription = e
	default:
		errorType = "unknown_error"
		errorDescription = fmt.Sprintf("%v", e)
	}

	response := map[string]interface{}{
		"status_code":       statusCode,
		"status_text":       http.StatusText(statusCode),
		"message":           message,
		"timestamp":         time.Now().Format(time.RFC3339),
		"error_type":        errorType,
		"error_description": errorDescription,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func checkStatusInstances(sqlService *sqladmin.Service, projectID string, instanceID string) (*SQLInstancesData, error) {
	instance, err := sqlService.Instances.Get(projectID, instanceID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get instances details, instances not found.: %w", err)
	}

	responseData := &SQLInstancesData{
		Name:            instance.Name,
		DatabaseVersion: instance.DatabaseVersion,
		Region:          instance.Region,
		State:           instance.State,
		Tier:            instance.Settings.Tier,
	}

	return responseData, nil
}
