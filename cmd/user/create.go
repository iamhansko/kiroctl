package user

import (
  "fmt"
  "os"
  "strings"

  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var createRegionFlag string
var givenNameFlag string
var familyNameFlag string
var emailFlag string

var CreateCmd = &cobra.Command{
  Use:   "create <USER_NAME>",
  Short: "사용자 생성",
  Long:  `create 명령어로 IAM Identity Center에서 새로운 사용자를 생성합니다.`,
  Args:  cobra.ExactArgs(1),
  Run: func(cmd *cobra.Command, args []string) {
    if err := createUser(args[0]); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  CreateCmd.Flags().StringVar(&createRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
  CreateCmd.Flags().StringVar(&givenNameFlag, "given-name", "", "사용자 이름 (필수)")
  CreateCmd.Flags().StringVar(&familyNameFlag, "family-name", "", "사용자 성 (필수)")
  CreateCmd.Flags().StringVar(&emailFlag, "email", "", "이메일 주소 (필수)")
  CreateCmd.MarkFlagRequired("given-name")
  CreateCmd.MarkFlagRequired("family-name")
  CreateCmd.MarkFlagRequired("email")
}

func createUser(userName string) error {
  region, err := utils.ValidateAndPrintRegion(createRegionFlag)
  if err != nil {
    return err
  }

  _, identityStoreId, err := utils.GetOrCreateInstance(region)
  if err != nil {
    return err
  }

  userId, err := utils.CreateIdentityStoreUser(region, identityStoreId, userName, givenNameFlag, familyNameFlag, emailFlag)
  if err != nil {
    return err
  }

  password, err := utils.GenerateUserPassword(region, userId)
  if err != nil {
    return fmt.Errorf("failed to generate password: %w", err)
  }

  fmt.Println("\n[ ⚠️ PLEASE SUBSCRIBE BEFORE YOU SIGN IN ]")
  fmt.Printf("Sign in URL : https://%s.awsapps.com/start\n", strings.TrimSpace(identityStoreId))
  fmt.Printf("Username    : %s\n", userName)
  fmt.Printf("Password    : %s\n", password)
  return nil
}
