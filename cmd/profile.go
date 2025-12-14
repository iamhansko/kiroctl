package cmd

import (
  "github.com/spf13/cobra"
  "kiroctl/cmd/profile"
)

var profileCmd = &cobra.Command{
  Use:   "profile",
  Short: "프로필 관리",
  Long:  `profile 명령어로 Kiro 프로필을 생성/삭제합니다.`,
}

func init() {
  rootCmd.AddCommand(profileCmd)
  profileCmd.AddCommand(profile.CreateCmd)
  profileCmd.AddCommand(profile.DeleteCmd)
  profileCmd.AddCommand(profile.StatusCmd)
}
