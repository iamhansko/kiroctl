package user

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var unsubscribeRegionFlag string

var UnsubscribeCmd = &cobra.Command{
  Use:     "unsubscribe <USER_ID>",
  Aliases: []string{"unsub"},
  Short:   "사용자 구독취소",
  Long:    `unsubscribe 명령어로 Kiro 사용자에 대한 구독취소를 요청합니다.`,
  Args:    cobra.ExactArgs(1),
  Run: func(cmd *cobra.Command, args []string) {
    if err := unsubscribe(args[0]); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  UnsubscribeCmd.Flags().StringVar(&unsubscribeRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func unsubscribe(userID string) error {
  region, err := utils.ValidateAndPrintRegion(unsubscribeRegionFlag)
  if err != nil {
    return err
  }

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.UserUnsubscribeRequest{
    PrincipalID:   userID,
    PrincipalType: utils.PrincipalTypeUser,
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "q",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AmazonQDeveloperService.DeleteAssignment",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  return utils.ExecuteAWSRequest(endpoint, config, authHeader, payloadHash, amzDate)
}
