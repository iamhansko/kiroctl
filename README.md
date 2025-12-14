# <img width="24" src="public/images/kiro.png"></img> kiroctl

kiroctl은 AWS IAM Identity Center 기반의 Kiro 환경을 관리하는 Go 언어 CLI 도구입니다. Cobra 라이브러리를 기반으로 개발되었으며, Kiro 프로필 및 사용자 구독 관리를 터미널에서 수행할 수 있습니다.

## 기능

- **Kiro 환경 초기화**: IAM Identity Center 인스턴스, Kiro 프로필, 사용자 생성 및 구독을 일괄 설정
- **Kiro 리소스 확인**: Kiro 리소스 상태 확인 (인스턴스, 프로필, 사용자, 구독)
- **Kiro 프로필 관리**: Kiro 프로필 생성, 삭제, 상태 조회
- **Kiro 사용자 관리**: Kiro 사용자 생성, 삭제, 목록 조회
- **Kiro 구독 관리**: 선택한 Kiro 요금제로 구독 및 구독 취소

### 지원 리전
- `us-east-1` (기본값)
- `eu-central-1`

## 설치 및 실행

### 사전 요구사항

- Go 1.16+
- AWS Credentials (Environment Variables or IMDS)
   
   ```bash
   export AWS_ACCESS_KEY_ID=<액세스 키>
   export AWS_SECRET_ACCESS_KEY=<시크릿 키>
   export AWS_SESSION_TOKEN=<세션 토큰>  # 임시 자격 증명 사용 시
   export AWS_DEFAULT_REGION=<리전> # us-east-1 또는 eu-central-1
   ```

```bash
kiroctl [command]
```

## 사용법

### kiro check

Kiro 환경을 사용할 준비가 되었는지 확인합니다. IAM Identity Center 인스턴스, Kiro 프로파일, Kiro 사용자, 구독 현황을 확인합니다.

```bash
kiroctl check
# or
kiroctl check --region us-east-1
# or
kiroctl check --region eu-central-1
```

### kiro init

Kiro 환경을 사용하기 위한 AWS 리소스를 일괄 생성합니다. IAM Identity Center 인스턴스, Kiro 프로필, 사용자가 자동으로 생성되고 생성된 사용자에 대한 [Kiro Pro](https://kiro.dev/pricing) 구독이 진행됩니다.

```bash
kiroctl init
# or
kiroctl init --region us-east-1
# or
kiroctl init --region eu-central-1
```

### kiro profile

```bash
# Kiro 프로필 생성
kiroctl profile create
# or
kiroctl profile create --region us-east-1
# or
kiroctl profile create --region eu-central-1


# Kiro 프로필 상태 조회
kiroctl profile status
# or
kiroctl profile status --region us-east-1
# or
kiroctl profile create --region eu-central-1


# Kiro 프로필 삭제
kiroctl profile delete
# or
kiroctl profile delete --region us-east-1
# or
kiroctl profile create --region eu-central-1
```

### kiroctl user

```bash
# 사용자 목록(ID) 조회
kiroctl user list
# or
kiroctl user list --region us-east-1
# or
kiroctl user list --region eu-central-1


# 사용자 생성
kiroctl user create --region us-east-1 <USER_NAME> \
--given-name Jane \
--family-name Doe \
--email jane@doe.com


# 사용자 삭제
kiroctl user delete <USER_ID>
# or
kiroctl user delete --region us-east-1 <USER_ID>


# 사용자 Kiro 구독 
# 요금제 : Q_DEVELOPER_STANDALONE_PRO[기본값] 또는 Q_DEVELOPER_STANDALONE_PRO_PLUS 또는 Q_DEVELOPER_STANDALONE_POWER
kiroctl user subscribe --region us-east-1 <USER_ID> --plan Q_DEVELOPER_STANDALONE_PRO
# or
kiroctl user sub --region us-east-1 <USER_ID> --plan Q_DEVELOPER_STANDALONE_PRO


# 사용자 Kiro 구독 취소
kiroctl user unsubscribe <USER_ID>
# or
kiroctl user unsubscribe --region us-east-1 <USER_ID>
# or
kiroctl user unsub <USER_ID>
```

## 프로젝트 구조

```
kiroctl/
├── main.go                      # 애플리케이션 진입점
├── cmd/                         # 명령어 구현
│   ├── root.go                  # 루트 명령어 정의
│   ├── check.go                 # 리소스 상태 확인
│   ├── clean.go                 # 리소스 정리
│   ├── init.go                  # 환경 초기화
│   ├── profile.go               # 프로필 명령어 그룹
│   ├── profile/
│   │   ├── create.go            # 프로필 생성
│   │   ├── delete.go            # 프로필 삭제
│   │   └── status.go            # 프로필 상태 조회
│   ├── user.go                  # 사용자 명령어 그룹
│   ├── user/
│   │   ├── create.go            # 사용자 생성
│   │   ├── delete.go            # 사용자 삭제
│   │   ├── list.go              # 사용자 목록 조회
│   │   ├── subscribe.go         # 사용자 구독
│   │   └── unsubscribe.go       # 사용자 구독 취소
│   └── utils/
│       ├── aws.go               # AWS API 유틸리티
│       ├── print.go             # 출력 유틸리티
│       └── types.go             # 공통 타입 정의
├── builds/                      # 빌드 출력 디렉토리
├── scripts/                     # 빌드 및 테스트 스크립트
├── go.mod                       # Go 모듈 정의
├── go.sum                       # 의존성 체크섬
└── README.md                    # 프로젝트 문서
```

### 빌드

#### 로컬 빌드

```bash
go build -o kiroctl
```

#### 크로스 플랫폼 빌드

**Linux:**
```bash
GOOS=linux GOARCH=amd64 go build -o builds/kiroctl
```

**Windows:**
```bash
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o builds/kiroctl.exe
```

## 의존성

### 주요 라이브러리

- **Cobra** (`github.com/spf13/cobra`)
- **AWS SDK for Go v2**:

### 의존성 관리

```bash
# 의존성 다운로드
go mod download

# 의존성 정리
go mod tidy
```

## 개발

### 하위 명령어 생성

1. `cmd/` 디렉토리에 새 파일 생성 (예: `cmd/newcommand.go`)
2. Cobra 명령어 정의
3. `init()` 함수에서 루트 명령어에 등록
4. 필요한 플래그 정의 및 검증 로직 추가

예제:
```go
package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
)

var newCmd = &cobra.Command{
    Use:   "new",
    Short: "새 명령어 설명",
    Long:  `새 명령어에 대한 상세 설명`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("NewCommand")
    },
}

func init() {
    rootCmd.AddCommand(newCmd)
    newCmd.Flags().String("flag", "", "플래그 설명")
}
```