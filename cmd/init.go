package cmd

import (
  "bufio"
  "context"
  "fmt"
  "os"
  "strings"
  "time"

  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/service/identitystore"
  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var initRegionFlag string

var initCmd = &cobra.Command{
  Use:   "init",
  Short: "Kiro 프로필 초기화",
  Long:  `init 명령어로 IAM Identity Center 인스턴스, Kiro 프로필, Kiro 기본 사용자를 생성하고 Q_DEVELOPER_STANDALONE_PRO 요금제로 구독합니다.`,
  Run: func(cmd *cobra.Command, args []string) {
    if err := initializeKiro(); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  initCmd.Flags().StringVar(&initRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
  rootCmd.AddCommand(initCmd)
}

func initializeKiro() error {
  region, err := utils.ValidateAndPrintRegion(initRegionFlag)
  if err != nil {
    return err
  }

  fmt.Printf("\n=== Kiro Environment Initialization (Region: %s) ===\n\n", region)

  fmt.Println("1. Checking IAM Identity Center instance...")
  instanceArn, identityStoreId, err := utils.GetOrCreateInstance(region)
  if err != nil {
    return fmt.Errorf("failed to verify/create instance: %w", err)
  }
  fmt.Printf("   ✓ Instance ARN: %s\n", instanceArn)
  fmt.Printf("   ✓ Identity Store ID: %s\n\n", identityStoreId)

  fmt.Println("2. Checking Kiro profile...")
  profileCreated, err := ensureProfile(region, instanceArn)
  if err != nil {
    return fmt.Errorf("failed to verify/create profile: %w", err)
  }

  if profileCreated {
    fmt.Println("   → Waiting for profile activation...")
    time.Sleep(15 * time.Second)
    fmt.Println("   ✓ Profile activated")
  }
  fmt.Println()

  fmt.Println("3. User Information Input")
  email, givenName, familyName, err := promptUserInfo()
  if err != nil {
    return fmt.Errorf("failed to input user information: %w", err)
  }
  fmt.Println()

  fmt.Println("4. Checking user...")
  userId, err := ensureUser(region, identityStoreId, email, givenName, familyName)
  if err != nil {
    return fmt.Errorf("failed to verify/create user: %w", err)
  }
  fmt.Printf("   ✓ User ID: %s\n", userId)

  fmt.Println("   → Generating password...")
  password, err := utils.GenerateUserPassword(region, userId)
  if err != nil {
    return fmt.Errorf("failed to generate password: %w", err)
  }
  fmt.Println("   ✓ Password generated")
  fmt.Println()

  fmt.Println("5. Configuring subscription...")
  if err := ensureSubscription(region, userId); err != nil {
    return fmt.Errorf("failed to configure subscription: %w", err)
  }

  fmt.Println("\n=== Kiro Environment Initialization Complete ===")
  fmt.Println()
  fmt.Println("[ Environment Information ]")
  fmt.Printf("Sign in URL : https://%s.awsapps.com/start\n", strings.TrimSpace(identityStoreId))
  fmt.Printf("Region      : %s\n", region)
  fmt.Printf("Username    : %s\n", email)
  fmt.Printf("Password    : %s\n", password)
  fmt.Println()
  return nil
}

func ensureProfile(region, instanceArn string) (bool, error) {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return false, err
  }

  existingProfile, err := utils.GetExistingProfile(region, accessKeyID, secretAccessKey, sessionToken)
  if err != nil {
    return false, fmt.Errorf("failed to query profile: %w", err)
  }

  if existingProfile != nil {
    fmt.Printf("   ✓ Existing profile found: %s (Status: %s)\n", existingProfile.ProfileName, existingProfile.Status)
    return false, nil
  }

  fmt.Println("   → Creating new profile...")
  created, err := utils.CreateProfileWithRetry(region, instanceArn, accessKeyID, secretAccessKey, sessionToken)
  if err != nil {
    return false, err
  }

  if created {
    fmt.Println("   ✓ Profile created")
  } else {
    fmt.Println("   ✓ Existing profile found")
  }

  return created, nil
}

func promptUserInfo() (email, givenName, familyName string, err error) {
  reader := bufio.NewReader(os.Stdin)

  fmt.Print("   Email: ")
  email, err = reader.ReadString('\n')
  if err != nil {
    return "", "", "", err
  }
  email = strings.TrimSpace(email)
  if email == "" {
    return "", "", "", fmt.Errorf("email is required")
  }

  fmt.Print("   Given Name (이름): ")
  givenName, err = reader.ReadString('\n')
  if err != nil {
    return "", "", "", err
  }
  givenName = strings.TrimSpace(givenName)
  if givenName == "" {
    return "", "", "", fmt.Errorf("given name is required")
  }

  fmt.Print("   Family Name (성): ")
  familyName, err = reader.ReadString('\n')
  if err != nil {
    return "", "", "", err
  }
  familyName = strings.TrimSpace(familyName)
  if familyName == "" {
    return "", "", "", fmt.Errorf("family name is required")
  }

  return email, givenName, familyName, nil
}

func ensureUser(region, identityStoreId, email, givenName, familyName string) (string, error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return "", fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := identitystore.NewFromConfig(cfg)

  listResult, err := client.ListUsers(ctx, &identitystore.ListUsersInput{
    IdentityStoreId: &identityStoreId,
  })
  if err != nil {
    return "", fmt.Errorf("failed to list identity store users: %w", err)
  }

  for _, user := range listResult.Users {
    if user.Emails != nil {
      for _, userEmail := range user.Emails {
        if userEmail.Value != nil && strings.EqualFold(*userEmail.Value, email) {
          fmt.Println("   ✓ Existing user found")
          return *user.UserId, nil
        }
      }
    }
  }

  fmt.Println("   → Creating new user...")
  userId, err := utils.CreateIdentityStoreUser(region, identityStoreId, email, givenName, familyName, email)
  if err != nil {
    return "", err
  }

  fmt.Println("   ✓ User created")
  return userId, nil
}

func ensureSubscription(region, userId string) error {
  accessKeyID, secretAccessKey, sessionToken, err := utils.GetAWSCredentials()
  if err != nil {
    return err
  }

  existingSubscription, err := utils.GetExistingSubscription(region, userId, accessKeyID, secretAccessKey, sessionToken)
  if err != nil {
    return fmt.Errorf("failed to query subscription: %w", err)
  }

  if existingSubscription != nil {
    fmt.Printf("   ✓ Existing subscription found (Status: %s, Plan: %s)\n", existingSubscription.Status, existingSubscription.Plan)
    return nil
  }

  fmt.Println("   → Creating new subscription...")
  err = utils.CreateSubscriptionWithRetry(region, userId, accessKeyID, secretAccessKey, sessionToken)
  if err != nil {
    return err
  }

  fmt.Println("   ✓ Subscription configured (Q_DEVELOPER_STANDALONE_PRO)")
  return nil
}
