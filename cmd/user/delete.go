package user

import (
  "context"
  "errors"
  "fmt"
  "os"

  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/service/identitystore"
  "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
  "github.com/spf13/cobra"
  "kiroctl/cmd/utils"
)

var deleteRegionFlag string

var DeleteCmd = &cobra.Command{
  Use:   "delete <USER_ID>",
  Short: "사용자 삭제",
  Long:  `delete 명령어로 IAM Identity Center에서 사용자를 삭제합니다.`,
  Args:  cobra.ExactArgs(1),
  Run: func(cmd *cobra.Command, args []string) {
    if err := deleteUser(args[0]); err != nil {
      fmt.Fprintf(os.Stderr, "Error: %v\n", err)
      os.Exit(1)
    }
  },
}

func init() {
  DeleteCmd.Flags().StringVar(&deleteRegionFlag, "region", "", "AWS 리전 (us-east-1[기본값] 또는 eu-central-1)")
}

func deleteUser(userId string) error {
  region, err := utils.ValidateAndPrintRegion(deleteRegionFlag)
  if err != nil {
    return err
  }

  _, identityStoreId, err := utils.GetInstanceInfo(region)
  if err != nil {
    return err
  }

  err = deleteIdentityStoreUser(region, identityStoreId, userId)
  if err != nil {
    return err
  }

  fmt.Printf("User %s deleted successfully.\n", userId)
  return nil
}

func deleteIdentityStoreUser(region, identityStoreId, userId string) error {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := identitystore.NewFromConfig(cfg)

  input := &identitystore.DeleteUserInput{
    IdentityStoreId: &identityStoreId,
    UserId:          &userId,
  }

  _, err = client.DeleteUser(ctx, input)
  if err != nil {
    var resourceNotFound *types.ResourceNotFoundException
    var accessDenied *types.AccessDeniedException

    if errors.As(err, &resourceNotFound) {
      return fmt.Errorf("user not found: %s", userId)
    }

    if errors.As(err, &accessDenied) {
      return fmt.Errorf("insufficient permissions. IAM permissions required to delete users from Identity Store: %w", err)
    }

    return fmt.Errorf("failed to delete user: %w", err)
  }

  return nil
}
