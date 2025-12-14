package profile

import (
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var statusRegionFlag string

var StatusCmd = &cobra.Command{
  Use:   "status",
  Short: "프로필 상태 조회",
  Long:  `status 명령어로 Kiro 프로필 상태를 조회합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := listProfiles(); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  StatusCmd.Flags().StringVar(&statusRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func listProfiles() error {
  region, err := utils.ValidateAndPrintRegion(statusRegionFlag)
  if err != nil {
    return err
  }

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.ListProfilesRequest{}
  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.ListProfiles",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := utils.CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return err
  }

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return fmt.Errorf("failed to read response: %w", err)
  }

  if resp.StatusCode != http.StatusOK {
    return fmt.Errorf("request failed with status %s: %s", resp.Status, string(body))
  }

  fmt.Printf("Status: %s\n", resp.Status)
  fmt.Printf("Response: %s\n", string(body))

  var response utils.ListProfilesResponse
  if err := json.Unmarshal(body, &response); err != nil {
    return fmt.Errorf("failed to parse response: %w", err)
  }

  if len(response.Profiles) > 0 {
    fmt.Println("\n[ 👻 Profile Details ]")
    utils.PrintProfileTable(response.Profiles[0])
  }

  return nil
}
