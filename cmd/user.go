package cmd

import (
  "github.com/spf13/cobra"
  "kiroctl/cmd/user"
)

var userCmd = &cobra.Command{
  Use:   "user",
  Short: "사용자 관리",
  Long:  `user 명령어로 Kiro 사용자를 구독/구독취소합니다.`,
}

func init() {
  rootCmd.AddCommand(userCmd)
  userCmd.AddCommand(user.SubscribeCmd)
  userCmd.AddCommand(user.UnsubscribeCmd)
  userCmd.AddCommand(user.ListCmd)
  userCmd.AddCommand(user.CreateCmd)
  userCmd.AddCommand(user.DeleteCmd)
}
