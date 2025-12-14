package cmd

import (
  "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
  Use:   "kiroctl",
  Short: "kiroctl은 Kiro 프로필 및 사용자/그룹 구독 관리를 위한 CLI 도구입니다",
  Long:  `kiroctl은 Cobra 라이브러리를 기반으로 개발된 Kiro 관리 도구입니다. CLI를 통해 Kiro 프로필 생성/삭제와 Kiro 사용자 및 그룹에 대한 구독/구독취소를 수행할 수 있습니다.`,
}

func Execute() error {
  return rootCmd.Execute()
}
