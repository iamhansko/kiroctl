package user

import (
  "encoding/json"
  "fmt"
  "os"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var subscribeRegionFlag string
var planFlag string

var SubscribeCmd = &cobra.Command{
  Use:     "subscribe <USER_ID>",
  Aliases: []string{"sub"},
  Short:   "사용자 구독",
  Long:    `subscribe 명령어로 Kiro 사용자에 대한 구독을 요청합니다. 선택 가능한 요금제는 Q_DEVELOPER_STANDALONE_PRO / Q_DEVELOPER_STANDALONE_PRO_PLUS / Q_DEVELOPER_STANDALONE_POWER 입니다.`,
  Args:    cobra.ExactArgs(1),
  Run: func(cmd *cobra.Command, args []string) {
    if err := createAssignment(args[0]); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  SubscribeCmd.Flags().StringVar(&subscribeRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
  SubscribeCmd.Flags().StringVar(&planFlag, "plan", "", "Kiro 요금제 (Q_DEVELOPER_STANDALONE_PRO[기본값] 또는 Q_DEVELOPER_STANDALONE_PRO_PLUS 또는 Q_DEVELOPER_STANDALONE_POWER)")
}

func createAssignment(userID string) error {
  plan := planFlag
  if plan == "" {
    plan = "Q_DEVELOPER_STANDALONE_PRO"
  }
  if plan != "Q_DEVELOPER_STANDALONE_PRO" && plan != "Q_DEVELOPER_STANDALONE_PRO_PLUS" && plan != "Q_DEVELOPER_STANDALONE_POWER" {
    return fmt.Errorf("only Q_DEVELOPER_STANDALONE_PRO, Q_DEVELOPER_STANDALONE_PRO_PLUS, Q_DEVELOPER_STANDALONE_POWER plans supported")
  }

  region, err := utils.ValidateAndPrintRegion(subscribeRegionFlag)
  if err != nil {
    return err
  }

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.UserSubscribeRequest{
    PrincipalID:      userID,
    PrincipalType:    utils.PrincipalTypeUser,
    SubscriptionType: plan,
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "q",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AmazonQDeveloperService.CreateAssignment",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  return utils.ExecuteAWSRequest(endpoint, config, authHeader, payloadHash, amzDate)
}
