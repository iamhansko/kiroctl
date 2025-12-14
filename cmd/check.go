package cmd

import (
  "context"
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"
  "time"

  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/service/identitystore"
  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var checkRegionFlag string
var debugFlag bool

var checkCmd = &cobra.Command{
  Use:   "check",
  Short: "Kiro 프로필 확인",
  Long:  `check 명령어로 IAM Identity Center 인스턴스, Kiro 프로파일, Kiro 사용자, 구독 현황을 확인합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := checkResources(); err != nil {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
      os.Exit(1)
    }
  },
}

func init() {
  checkCmd.Flags().StringVar(&checkRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
  checkCmd.Flags().BoolVar(&debugFlag, "debug", false, "디버그 메시지 출력")
  rootCmd.AddCommand(checkCmd)
}

func checkResources() error {
  region, err := utils.ValidateAndPrintRegion(checkRegionFlag)
  if err != nil {
    return err
  }

  passedCount := 0

  instanceArn, instanceExists := checkIdentityCenterInstance(region)
  if !instanceExists {
    fmt.Printf("❌ IAM Identity Center Instance\n")
  } else {
    fmt.Printf("✅ IAM Identity Center Instance : %s\n", instanceArn)
    passedCount++
  }

  profileName, profileExists := checkProfile(region)
  if profileExists {
    fmt.Printf("✅ Kiro Profile : %s\n", profileName)
    passedCount++
  } else {
    fmt.Printf("❌ Kiro Profile\n")
  }

  userCount := 0
  if instanceExists {
    userCount = checkUsers(region, instanceArn)
  }
  if userCount > 0 {
    fmt.Printf("✅ %d User(s)\n", userCount)
    passedCount++
  } else {
    fmt.Printf("❌ 0 User(s)\n")
  }

  subscriptionCount := 0
  if instanceExists {
    subscriptionCount = checkSubscriptions(region, instanceArn)
  }
  if subscriptionCount > 0 {
    fmt.Printf("✅ %d Subscription(s)\n", subscriptionCount)
    passedCount++
  } else {
    fmt.Printf("❌ 0 Subscription(s)\n")
  }

  if passedCount == 4 {
    fmt.Printf("\n"+utils.ColorGreen+"( \033[1m%d\033[0m"+utils.ColorGreen+"/4 Passed )\n"+utils.ColorReset, passedCount)
  } else {
    fmt.Printf("\n"+utils.ColorRed+"( \033[1m%d\033[0m"+utils.ColorRed+"/4 Passed )\n"+utils.ColorReset, passedCount)
  }

  return nil
}

func checkIdentityCenterInstance(region string) (string, bool) {
  instanceArn, _, err := utils.GetInstanceInfo(region)
  if err != nil {
    return "", false
  }
  return instanceArn, true
}

func checkProfile(region string) (string, bool) {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return "", false
  }

  profile, err := utils.GetExistingProfile(region, accessKeyID, secretAccessKey, sessionToken)
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return "", false
  }

  if profile == nil {
    return "", false
  }

  if debugFlag {
    fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Found profile: %s\n"+utils.ColorReset, profile.ProfileName)
  }

  return profile.ProfileName, true
}

func checkUsers(region string, instanceArn string) int {
  ctx := context.TODO()

  _, identityStoreId, err := utils.GetInstanceInfo(region)
  if err != nil {
    return 0
  }

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return 0
  }

  identityClient := identitystore.NewFromConfig(cfg)
  userResult, err := identityClient.ListUsers(ctx, &identitystore.ListUsersInput{
    IdentityStoreId: &identityStoreId,
  })
  if err != nil {
    return 0
  }

  return len(userResult.Users)
}

func checkSubscriptions(region string, instanceArn string) int {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }

  requestBodyStruct := map[string]interface{}{
    "instanceArn":        instanceArn,
    "maxResults":         utils.DefaultMaxResults,
    "subscriptionRegion": region,
  }

  requestBody, err := json.Marshal(requestBodyStruct)
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "user-subscriptions",
    Host:         fmt.Sprintf("service.user-subscriptions.%s.amazonaws.com", region),
    Target:       "AWSZornControlPlaneService.ListUserSubscriptions",
    UserAgent:    "aws-sdk-js/1.0.0 ua/2.0",
    RequestBody:  requestBody,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := utils.CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }

  client := &http.Client{Timeout: 10 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }

  if resp.StatusCode != http.StatusOK {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Subscription API status code: %d\n"+utils.ColorReset, resp.StatusCode)
      fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Subscription API response: %s\n"+utils.ColorReset, string(body))
    }
    return 0
  }

  if debugFlag {
    fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Subscription API response: %s\n"+utils.ColorReset, string(body))
  }

  var result map[string]interface{}
  if err := json.Unmarshal(body, &result); err != nil {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] %v\n"+utils.ColorReset, err)
    }
    return 0
  }

  subscriptions, ok := result["subscriptions"].([]interface{})
  if !ok {
    if debugFlag {
      fmt.Fprintf(os.Stderr, utils.ColorRed+"[ERROR] Subscriptions field is not an array\n"+utils.ColorReset)
    }
    return 0
  }

  activeCount := 0
  for _, sub := range subscriptions {
    subscription, ok := sub.(map[string]interface{})
    if !ok {
      continue
    }

    status, ok := subscription["status"].(string)
    if !ok {
      continue
    }

    if status != "CANCELLED" {
      activeCount++
    } else {
      if debugFlag {
        fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Excluding CANCELLED subscription\n"+utils.ColorReset)
      }
    }
  }

  if debugFlag {
    fmt.Fprintf(os.Stderr, utils.ColorYellow+"[DEBUG] Total subscriptions: %d, Active subscriptions: %d\n"+utils.ColorReset, len(subscriptions), activeCount)
  }
  return activeCount
}
