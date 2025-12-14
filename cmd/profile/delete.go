package profile

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var deleteRegionFlag string

var DeleteCmd = &cobra.Command{
  Use:   "delete",
  Short: "프로필 삭제",
  Long:  `delete 명령어로 Kiro 프로필을 삭제합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := deleteProfile(); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  DeleteCmd.Flags().StringVar(&deleteRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func deleteProfile() error {
  region, err := utils.ValidateAndPrintRegion(deleteRegionFlag)
  if err != nil {
    return err
  }

  profileArn, err := utils.GetProfileArn(region)
  if err != nil {
    return err
  }

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.DeleteProfileRequest{
    ProfileArn: profileArn,
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.DeleteProfile",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  return utils.ExecuteAWSRequest(endpoint, config, authHeader, payloadHash, amzDate)
}
