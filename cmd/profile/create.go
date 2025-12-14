package profile

import (
  "encoding/json"
  "fmt"
  "os"
  "time"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var regionFlag string

var CreateCmd = &cobra.Command{
  Use:   "create",
  Short: "프로필 생성",
  Long:  `create 명령어로 IAM Identity Center 인스턴스와 연동하여 새로운 Kiro 프로필을 생성합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := createProfile(); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  CreateCmd.Flags().StringVar(&regionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func createProfile() error {
  region, err := utils.ValidateAndPrintRegion(regionFlag)
  if err != nil {
    return err
  }

  instanceArn, _, err := utils.GetOrCreateInstance(region)
  if err != nil {
    return err
  }

  fmt.Printf("IAM Identity Center Instance: %s\n", instanceArn)

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.BuildCreateProfileRequest(region, instanceArn)
  requestBody.ClientToken = fmt.Sprintf("%d", time.Now().UnixNano())

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.CreateProfile",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  return utils.ExecuteAWSRequest(endpoint, config, authHeader, payloadHash, amzDate)
}
