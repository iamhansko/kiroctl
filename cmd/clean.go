package cmd

import (
  "context"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "net/http"
  "os"
  "time"

  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/service/identitystore"
  identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
  "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
  ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var cleanRegionFlag string

var cleanCmd = &cobra.Command{
  Use:   "clean",
  Short: "구독취소 및 프로필/사용자/인스턴스 일괄 삭제",
  Long:  `clean 명령어로 모든 Kiro 구독을 취소하고 Kiro 프로필과 IAM Identity Center 사용자/인스턴스를 삭제합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := cleanResources(); err != nil {
      utils.PrintError("%v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  cleanCmd.Flags().StringVar(&cleanRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
  rootCmd.AddCommand(cleanCmd)
}

type CleanSubscriptionInfo struct {
  UserID string
  Status string
  Plan   string
}

type UserInfo struct {
  UserID      string
  UserName    string
  Email       string
  DisplayName string
}

type InstanceInfo struct {
  InstanceArn     string
  IdentityStoreId string
}

type ResourceSummary struct {
  Subscriptions []CleanSubscriptionInfo
  Profile       *utils.ProfileInfo
  Users         []UserInfo
  Instance      *InstanceInfo
}

type DeletionResult struct {
  ResourceType string
  Success      bool
  Error        error
  Details      string
}

func queryProfile(region string) (*utils.ProfileInfo, error) {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return nil, fmt.Errorf("failed to get AWS credentials: %w", err)
  }

  requestBody := []byte("{}")

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.ListProfiles",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBody,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := utils.CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return nil, fmt.Errorf("failed to create HTTP request: %w", err)
  }

  client := &http.Client{Timeout: 10 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return nil, fmt.Errorf("failed to read response body: %w", err)
  }

  if resp.StatusCode != http.StatusOK {
    utils.PrintDebug("Profile API status code: %d\n", resp.StatusCode)
    utils.PrintDebug("Profile API response: %s\n", string(body))
    return nil, nil
  }

  var result map[string]interface{}
  if err := json.Unmarshal(body, &result); err != nil {
    return nil, fmt.Errorf("failed to parse JSON response: %w", err)
  }

  profiles, ok := result["profiles"].([]interface{})
  if !ok || len(profiles) == 0 {
    return nil, nil
  }

  firstProfile, ok := profiles[0].(map[string]interface{})
  if !ok {
    return nil, fmt.Errorf("invalid profile format")
  }

  profileName, _ := firstProfile["profileName"].(string)
  profileArn, _ := firstProfile["arn"].(string)
  profileStatus, _ := firstProfile["status"].(string)

  return &utils.ProfileInfo{
    ProfileName: profileName,
    Arn:         profileArn,
    Status:      profileStatus,
  }, nil
}

func queryUsers(region string, identityStoreId string) ([]UserInfo, error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return nil, fmt.Errorf("failed to load AWS config: %w", err)
  }

  identityClient := identitystore.NewFromConfig(cfg)
  userResult, err := identityClient.ListUsers(ctx, &identitystore.ListUsersInput{
    IdentityStoreId: &identityStoreId,
  })
  if err != nil {
    return nil, fmt.Errorf("failed to list users: %w", err)
  }

  users := make([]UserInfo, 0, len(userResult.Users))
  for _, user := range userResult.Users {
    userInfo := UserInfo{
      UserID:   *user.UserId,
      UserName: *user.UserName,
    }

    for _, email := range user.Emails {
      if email.Value != nil {
        userInfo.Email = *email.Value
        break
      }
    }

    if user.DisplayName != nil {
      userInfo.DisplayName = *user.DisplayName
    }

    users = append(users, userInfo)
  }

  return users, nil
}

func querySubscriptions(region string, instanceArn string) ([]CleanSubscriptionInfo, error) {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return nil, fmt.Errorf("failed to get AWS credentials: %w", err)
  }

  requestBodyStruct := map[string]interface{}{
    "instanceArn":        instanceArn,
    "maxResults":         utils.DefaultMaxResults,
    "subscriptionRegion": region,
  }

  requestBody, err := json.Marshal(requestBodyStruct)
  if err != nil {
    return nil, fmt.Errorf("failed to marshal request body: %w", err)
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
    return nil, fmt.Errorf("failed to create HTTP request: %w", err)
  }

  client := &http.Client{Timeout: 10 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return nil, fmt.Errorf("failed to read response body: %w", err)
  }

  if resp.StatusCode != http.StatusOK {
    utils.PrintDebug("Subscription API status code: %d\n", resp.StatusCode)
    utils.PrintDebug("Subscription API response: %s\n", string(body))
    return nil, nil
  }

  var result map[string]interface{}
  if err := json.Unmarshal(body, &result); err != nil {
    return nil, fmt.Errorf("failed to parse JSON response: %w", err)
  }

  subscriptions, ok := result["subscriptions"].([]interface{})
  if !ok {
    return []CleanSubscriptionInfo{}, nil
  }

  activeSubscriptions := make([]CleanSubscriptionInfo, 0)
  for _, sub := range subscriptions {
    subscription, ok := sub.(map[string]interface{})
    if !ok {
      continue
    }

    status, _ := subscription["status"].(string)
    if status == "CANCELLED" {
      continue
    }

    var userID string
    if principal, ok := subscription["principal"].(map[string]interface{}); ok {
      userID, _ = principal["user"].(string)
    }

    var plan string
    if typeInfo, ok := subscription["type"].(map[string]interface{}); ok {
      plan, _ = typeInfo["amazonQ"].(string)
    }

    activeSubscriptions = append(activeSubscriptions, CleanSubscriptionInfo{
      UserID: userID,
      Status: status,
      Plan:   plan,
    })
  }

  return activeSubscriptions, nil
}

func queryAllResources(region string) (*ResourceSummary, error) {
  summary := &ResourceSummary{}

  instanceArn, identityStoreId, err := utils.GetInstanceInfo(region)
  if err != nil {
    return nil, fmt.Errorf("failed to query instance: %w", err)
  }

  if instanceArn == "" {
    utils.PrintInfo("No IAM Identity Center instance found.\n")
    return summary, nil
  }

  summary.Instance = &InstanceInfo{
    InstanceArn:     instanceArn,
    IdentityStoreId: identityStoreId,
  }

  profile, err := queryProfile(region)
  if err != nil {
    utils.PrintDebug("Failed to query profile: %v\n", err)
  } else {
    summary.Profile = profile
  }

  users, err := queryUsers(region, identityStoreId)
  if err != nil {
    utils.PrintDebug("Failed to query users: %v\n", err)
  } else {
    summary.Users = users
  }

  subscriptions, err := querySubscriptions(region, instanceArn)
  if err != nil {
    utils.PrintDebug("Failed to query subscriptions: %v\n", err)
  } else {
    summary.Subscriptions = subscriptions
  }

  return summary, nil
}

func confirmDeletion() bool {
  utils.PrintInfo("Do you want to delete all the above resources? (Y/N): ")

  var input string
  _, err := fmt.Scanln(&input)
  if err != nil {
    utils.PrintError("Failed to read input: %v\n", err)
    return false
  }

  if input == "Y" || input == "y" {
    return true
  }

  if input == "N" || input == "n" {
    return false
  }

  utils.PrintError("Invalid input: %s. Please enter Y or N.\n", input)
  return false
}

func displayResources(summary *ResourceSummary) {
  hasResources := false

  utils.PrintInfo("\n[ Affected Resources ]\n")

  if len(summary.Subscriptions) > 0 {
    hasResources = true
    utils.PrintInfo("🖊️ %d Subscription(s) :\n", len(summary.Subscriptions))
    for _, sub := range summary.Subscriptions {
      utils.PrintInfo("  - User ID: %s\n", sub.UserID)
      utils.PrintInfo("    Status: %s\n", sub.Status)
      utils.PrintInfo("    Plan: %s\n", sub.Plan)
    }
    utils.PrintInfo("\n")
  }

  if summary.Profile != nil {
    hasResources = true
    utils.PrintInfo("👻 Kiro Profile :\n")
    utils.PrintInfo("  - Name: %s\n", summary.Profile.ProfileName)
    utils.PrintInfo("    ARN: %s\n", summary.Profile.Arn)
    utils.PrintInfo("    Status: %s\n", summary.Profile.Status)
    utils.PrintInfo("\n")
  }

  if len(summary.Users) > 0 {
    hasResources = true
    utils.PrintInfo("👥 %d User(s) :\n", len(summary.Users))
    for _, user := range summary.Users {
      utils.PrintInfo("  - Username: %s\n", user.UserName)
      utils.PrintInfo("    ID: %s\n", user.UserID)
      if user.Email != "" {
        utils.PrintInfo("    Email: %s\n", user.Email)
      }
      if user.DisplayName != "" {
        utils.PrintInfo("    Display Name: %s\n", user.DisplayName)
      }
    }
    utils.PrintInfo("\n")
  }

  if summary.Instance != nil {
    hasResources = true
    utils.PrintInfo("🔒 IAM Identity Center Instance :\n")
    utils.PrintInfo("  - ARN: %s\n", summary.Instance.InstanceArn)
    utils.PrintInfo("  - Identity Store ID: %s\n", summary.Instance.IdentityStoreId)
    utils.PrintInfo("\n")
  }

  if !hasResources {
    utils.PrintInfo("No Resources to delete\n")
  }
}

func unsubscribeAll(region string, subscriptions []CleanSubscriptionInfo) []DeletionResult {
  results := make([]DeletionResult, 0, len(subscriptions))

  if len(subscriptions) == 0 {
    return results
  }

  utils.PrintInfo("\nUnsubscribing...\n")

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    utils.PrintError("Failed to get AWS credentials: %v\n", err)
    for _, sub := range subscriptions {
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      false,
        Error:        err,
        Details:      sub.UserID,
      })
    }
    return results
  }

  for _, sub := range subscriptions {
    utils.PrintDebug("Unsubscribing user: %s\n", sub.UserID)

    requestBodyStruct := map[string]interface{}{
      "principalId":   sub.UserID,
      "principalType": utils.PrincipalTypeUser,
    }

    requestBody, err := json.Marshal(requestBodyStruct)
    if err != nil {
      utils.PrintError("Failed to marshal request body for user %s: %v\n", sub.UserID, err)
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      false,
        Error:        err,
        Details:      sub.UserID,
      })
      continue
    }

    config := utils.AWSRequestConfig{
      Region:       region,
      Service:      "q",
      Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
      Target:       "AmazonQDeveloperService.DeleteAssignment",
      UserAgent:    "aws-sdk-js/2.1692.0 promise",
      RequestBody:  requestBody,
      SessionToken: sessionToken,
    }

    endpoint := fmt.Sprintf("https://%s/", config.Host)
    authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

    req, err := utils.CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
    if err != nil {
      utils.PrintError("Failed to create HTTP request for user %s: %v\n", sub.UserID, err)
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      false,
        Error:        err,
        Details:      sub.UserID,
      })
      continue
    }

    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
      utils.PrintError("Failed to execute HTTP request for user %s: %v\n", sub.UserID, err)
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      false,
        Error:        err,
        Details:      sub.UserID,
      })
      continue
    }

    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
      utils.PrintDebug("Subscription for user %s already deleted (404)\n", sub.UserID)
      utils.PrintInfo("  ✅ %s (already deleted)\n", sub.UserID)
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      true,
        Details:      sub.UserID + " (already deleted)",
      })
      continue
    }

    if resp.StatusCode != http.StatusOK {
      errMsg := fmt.Sprintf("API returned status %d: %s", resp.StatusCode, string(body))
      utils.PrintError("Failed to unsubscribe user %s: %s\n", sub.UserID, errMsg)
      results = append(results, DeletionResult{
        ResourceType: "Subscription",
        Success:      false,
        Error:        fmt.Errorf("%s", errMsg),
        Details:      sub.UserID,
      })
      continue
    }

    utils.PrintInfo("  ✅ %s\n", sub.UserID)
    results = append(results, DeletionResult{
      ResourceType: "Subscription",
      Success:      true,
      Details:      sub.UserID,
    })
  }

  return results
}

func deleteProfile(region string, profile *utils.ProfileInfo) DeletionResult {
  if profile == nil {
    return DeletionResult{
      ResourceType: "Profile",
      Success:      true,
      Details:      "No profile to delete",
    }
  }

  utils.PrintInfo("\nDeleting profile...\n")
  utils.PrintDebug("Deleting profile: %s (ARN: %s)\n", profile.ProfileName, profile.Arn)

  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    utils.PrintError("Failed to get AWS credentials: %v\n", err)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      false,
      Error:        err,
      Details:      profile.ProfileName,
    }
  }

  requestBodyStruct := map[string]interface{}{
    "profileArn": profile.Arn,
  }

  requestBody, err := json.Marshal(requestBodyStruct)
  if err != nil {
    utils.PrintError("Failed to marshal request body: %v\n", err)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      false,
      Error:        err,
      Details:      profile.ProfileName,
    }
  }

  config := utils.AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.DeleteProfile",
    UserAgent:    "aws-sdk-js/2.1692.0 promise",
    RequestBody:  requestBody,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := utils.CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := utils.CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    utils.PrintError("Failed to create HTTP request: %v\n", err)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      false,
      Error:        err,
      Details:      profile.ProfileName,
    }
  }

  client := &http.Client{Timeout: 10 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    utils.PrintError("Failed to execute HTTP request: %v\n", err)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      false,
      Error:        err,
      Details:      profile.ProfileName,
    }
  }

  body, _ := io.ReadAll(resp.Body)
  resp.Body.Close()

  if resp.StatusCode == http.StatusNotFound {
    utils.PrintDebug("Profile %s already deleted (404)\n", profile.ProfileName)
    utils.PrintInfo("  ✅ %s (already deleted)\n", profile.ProfileName)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      true,
      Details:      profile.ProfileName + " (already deleted)",
    }
  }

  if resp.StatusCode != http.StatusOK {
    errMsg := fmt.Sprintf("API returned status %d: %s", resp.StatusCode, string(body))
    utils.PrintError("Failed to delete profile %s: %s\n", profile.ProfileName, errMsg)
    return DeletionResult{
      ResourceType: "Profile",
      Success:      false,
      Error:        fmt.Errorf("%s", errMsg),
      Details:      profile.ProfileName,
    }
  }

  utils.PrintInfo("  ✅ %s\n", profile.ProfileName)
  return DeletionResult{
    ResourceType: "Profile",
    Success:      true,
    Details:      profile.ProfileName,
  }
}

func deleteAllUsers(region string, identityStoreId string, users []UserInfo) []DeletionResult {
  results := make([]DeletionResult, 0, len(users))

  if len(users) == 0 {
    return results
  }

  utils.PrintInfo("\nDeleting users...\n")

  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    utils.PrintError("Failed to load AWS config: %v\n", err)
    for _, user := range users {
      results = append(results, DeletionResult{
        ResourceType: "User",
        Success:      false,
        Error:        err,
        Details:      user.UserName,
      })
    }
    return results
  }

  client := identitystore.NewFromConfig(cfg)

  for _, user := range users {
    utils.PrintDebug("Deleting user: %s (ID: %s)\n", user.UserName, user.UserID)

    input := &identitystore.DeleteUserInput{
      IdentityStoreId: &identityStoreId,
      UserId:          &user.UserID,
    }

    _, err := client.DeleteUser(ctx, input)
    if err != nil {
      var resourceNotFound *identitystoretypes.ResourceNotFoundException
      if errors.As(err, &resourceNotFound) {
        utils.PrintDebug("User %s already deleted (404)\n", user.UserName)
        utils.PrintInfo("  ✅ %s (already deleted)\n", user.UserName)
        results = append(results, DeletionResult{
          ResourceType: "User",
          Success:      true,
          Details:      user.UserName + " (already deleted)",
        })
        continue
      }

      utils.PrintError("Failed to delete user %s: %v\n", user.UserName, err)
      results = append(results, DeletionResult{
        ResourceType: "User",
        Success:      false,
        Error:        err,
        Details:      user.UserName,
      })
      continue
    }

    utils.PrintInfo("  ✅ %s\n", user.UserName)
    results = append(results, DeletionResult{
      ResourceType: "User",
      Success:      true,
      Details:      user.UserName,
    })
  }

  return results
}

func deleteInstance(region string, instance *InstanceInfo) DeletionResult {
  if instance == nil {
    return DeletionResult{
      ResourceType: "Instance",
      Success:      true,
      Details:      "No instance to delete",
    }
  }

  utils.PrintInfo("\nDeleting IAM Identity Center instance...\n")
  utils.PrintDebug("Deleting instance: %s\n", instance.InstanceArn)

  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    utils.PrintError("Failed to load AWS config: %v\n", err)
    return DeletionResult{
      ResourceType: "Instance",
      Success:      false,
      Error:        err,
      Details:      instance.InstanceArn,
    }
  }

  client := ssoadmin.NewFromConfig(cfg)

  input := &ssoadmin.DeleteInstanceInput{
    InstanceArn: &instance.InstanceArn,
  }

  _, err = client.DeleteInstance(ctx, input)
  if err != nil {
    var resourceNotFound *ssoadmintypes.ResourceNotFoundException
    if errors.As(err, &resourceNotFound) {
      utils.PrintDebug("Instance %s already deleted (404)\n", instance.InstanceArn)
      utils.PrintInfo("  ✅ %s (already deleted)\n", instance.InstanceArn)
      return DeletionResult{
        ResourceType: "Instance",
        Success:      true,
        Details:      instance.InstanceArn + " (already deleted)",
      }
    }

    utils.PrintError("Failed to delete instance %s: %v\n", instance.InstanceArn, err)
    return DeletionResult{
      ResourceType: "Instance",
      Success:      false,
      Error:        err,
      Details:      instance.InstanceArn,
    }
  }

  utils.PrintInfo("  ✅ %s\n", instance.InstanceArn)
  return DeletionResult{
    ResourceType: "Instance",
    Success:      true,
    Details:      instance.InstanceArn,
  }
}

func summarizeResults(results []DeletionResult) error {
  utils.PrintInfo("\n=== Deletion Summary ===\n\n")

  successCount := 0
  failureCount := 0
  failures := make([]DeletionResult, 0)

  for _, result := range results {
    if result.Success {
      successCount++
      utils.PrintInfo("✅ %s: %s\n", result.ResourceType, result.Details)
    } else {
      failureCount++
      failures = append(failures, result)
      utils.PrintError("❌ %s: %s - %v\n", result.ResourceType, result.Details, result.Error)
    }
  }

  utils.PrintInfo("\n")

  if failureCount == 0 && successCount > 0 {
    utils.PrintSuccess("All Resources Deleted\n")
    return nil
  }

  if failureCount > 0 {
    utils.PrintError("\n%d resource(s) failed to delete:\n", failureCount)
    for _, failure := range failures {
      utils.PrintError("  - %s: %s\n", failure.ResourceType, failure.Details)
    }
    return fmt.Errorf("%d deletion(s) failed", failureCount)
  }

  return nil
}

func cleanResources() error {
  region, err := utils.ValidateAndPrintRegion(cleanRegionFlag)
  if err != nil {
    return err
  }

  summary, err := queryAllResources(region)
  if err != nil {
    return fmt.Errorf("failed to query resources: %w", err)
  }

  displayResources(summary)

  hasResources := len(summary.Subscriptions) > 0 || summary.Profile != nil || len(summary.Users) > 0 || summary.Instance != nil
  if !hasResources {
    return nil
  }

  if !confirmDeletion() {
    utils.PrintInfo("Operation cancelled.\n")
    return nil
  }

  utils.PrintInfo("\nStarting deletion...\n")
  results := []DeletionResult{}

  if len(summary.Subscriptions) > 0 {
    subscriptionResults := unsubscribeAll(region, summary.Subscriptions)
    results = append(results, subscriptionResults...)
  }

  if summary.Profile != nil {
    profileResult := deleteProfile(region, summary.Profile)
    results = append(results, profileResult)
  }

  if len(summary.Users) > 0 && summary.Instance != nil {
    userResults := deleteAllUsers(region, summary.Instance.IdentityStoreId, summary.Users)
    results = append(results, userResults...)
  }

  if summary.Instance != nil {
    instanceResult := deleteInstance(region, summary.Instance)
    results = append(results, instanceResult)
  }

  return summarizeResults(results)
}
