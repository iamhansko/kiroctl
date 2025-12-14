package user

import (
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var listRegionFlag string

var ListCmd = &cobra.Command{
  Use:     "list",
  Aliases: []string{"ls"},
  Short:   "사용자 구독 목록 조회",
  Long:    `list 명령어로 Kiro 사용자 구독 목록을 조회합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := listUserSubscriptions(); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  ListCmd.Flags().StringVar(&listRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func listUserSubscriptions() error {
  region, err := utils.ValidateAndPrintRegion(listRegionFlag)
  if err != nil {
    return err
  }

  instanceArn, identityStoreId, err := utils.GetInstanceInfo(region)
  if err != nil {
    return err
  }

  identityStoreUsers, err := utils.ListIdentityStoreUsers(region, identityStoreId)
  if err != nil {
    return err
  }

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  requestBody := utils.ListUserSubscriptionsRequest{
    InstanceArn:        instanceArn,
    MaxResults:         utils.DefaultMaxResults,
    SubscriptionRegion: region,
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "user-subscriptions",
    Host:         fmt.Sprintf("service.user-subscriptions.%s.amazonaws.com", region),
    Target:       "AWSZornControlPlaneService.ListUserSubscriptions",
    UserAgent:    "aws-sdk-js/1.0.0 ua/2.0",
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

  var response utils.ListUserSubscriptionsResponse
  if err := json.Unmarshal(body, &response); err != nil {
    return fmt.Errorf("failed to parse response: %w", err)
  }

  fmt.Println("\n[ 🔒 IAM Identity Center Users ]")
  utils.PrintIdentityStoreUsersTable(identityStoreUsers)

  fmt.Println("\n[ 👻 Kiro Subscriptions ]")
  utils.PrintSubscriptionsTable(response.Subscriptions)

  return nil
}
