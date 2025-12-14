#!/bin/bash

# kiroctl 기능 테스트 스크립트
# 모든 명령어의 기본 동작을 검증합니다

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 테스트 결과 카운터
PASSED=0
FAILED=0

# 로그 함수
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 구분선 출력
print_separator() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
    echo ""
}

# kiroctl 바이너리 확인
check_binary() {
    if [ ! -f "./builds/kiroctl" ] && [ ! -f "./builds/kiroctl.exe" ]; then
        log_error "kiroctl 바이너리를 찾을 수 없습니다. 먼저 빌드하세요: go build -o kiroctl"
        exit 1
    fi
    
    if [ -f "./builds/kiroctl.exe" ]; then
        KIROCTL="./builds/kiroctl.exe"
    else
        KIROCTL="./builds/kiroctl"
    fi
    
    log_success "kiroctl 바이너리 확인: $KIROCTL"
}

# 명령어 도움말 테스트
test_help() {
    print_separator "도움말 명령어 테스트"
    
    if $KIROCTL --help > /dev/null 2>&1; then
        log_success "kiroctl --help"
    else
        log_error "kiroctl --help"
    fi
    
    if $KIROCTL -h > /dev/null 2>&1; then
        log_success "kiroctl -h"
    else
        log_error "kiroctl -h"
    fi
}

# check 명령어 테스트
test_check() {
    print_separator "check 명령어 테스트"
    
    # 도움말
    if $KIROCTL check --help > /dev/null 2>&1; then
        log_success "kiroctl check --help"
    else
        log_error "kiroctl check --help"
    fi
    
    # 기본 리전 (us-east-1)
    log_info "kiroctl check (기본 리전) 실행 중..."
    if $KIROCTL check > /dev/null 2>&1; then
        log_success "kiroctl check (기본 리전)"
    else
        log_warning "kiroctl check (기본 리전) - AWS 자격 증명 필요"
    fi
    
    # 특정 리전
    log_info "kiroctl check --region eu-central-1 실행 중..."
    if $KIROCTL check --region eu-central-1 > /dev/null 2>&1; then
        log_success "kiroctl check --region eu-central-1"
    else
        log_warning "kiroctl check --region eu-central-1 - AWS 자격 증명 필요"
    fi
}

# init 명령어 테스트
test_init() {
    print_separator "init 명령어 테스트"
    
    # 도움말
    if $KIROCTL init --help > /dev/null 2>&1; then
        log_success "kiroctl init --help"
    else
        log_error "kiroctl init --help"
    fi
    
    log_warning "kiroctl init - 대화형 명령어로 자동 테스트 생략"
}

# clean 명령어 테스트
test_clean() {
    print_separator "clean 명령어 테스트"
    
    # 도움말
    if $KIROCTL clean --help > /dev/null 2>&1; then
        log_success "kiroctl clean --help"
    else
        log_error "kiroctl clean --help"
    fi
    
    log_warning "kiroctl clean - 파괴적 명령어로 자동 테스트 생략"
}

# profile 명령어 테스트
test_profile() {
    print_separator "profile 명령어 테스트"
    
    # 그룹 도움말
    if $KIROCTL profile --help > /dev/null 2>&1; then
        log_success "kiroctl profile --help"
    else
        log_error "kiroctl profile --help"
    fi
    
    # profile create
    if $KIROCTL profile create --help > /dev/null 2>&1; then
        log_success "kiroctl profile create --help"
    else
        log_error "kiroctl profile create --help"
    fi
    
    # profile delete
    if $KIROCTL profile delete --help > /dev/null 2>&1; then
        log_success "kiroctl profile delete --help"
    else
        log_error "kiroctl profile delete --help"
    fi
    
    # profile status
    if $KIROCTL profile status --help > /dev/null 2>&1; then
        log_success "kiroctl profile status --help"
    else
        log_error "kiroctl profile status --help"
    fi
    
    log_info "kiroctl profile status 실행 중..."
    if $KIROCTL profile status > /dev/null 2>&1; then
        log_success "kiroctl profile status"
    else
        log_warning "kiroctl profile status - AWS 자격 증명 필요"
    fi
}

# user 명령어 테스트
test_user() {
    print_separator "user 명령어 테스트"
    
    # 그룹 도움말
    if $KIROCTL user --help > /dev/null 2>&1; then
        log_success "kiroctl user --help"
    else
        log_error "kiroctl user --help"
    fi
    
    # user create
    if $KIROCTL user create --help > /dev/null 2>&1; then
        log_success "kiroctl user create --help"
    else
        log_error "kiroctl user create --help"
    fi
    
    # user delete
    if $KIROCTL user delete --help > /dev/null 2>&1; then
        log_success "kiroctl user delete --help"
    else
        log_error "kiroctl user delete --help"
    fi
    
    # user list
    if $KIROCTL user list --help > /dev/null 2>&1; then
        log_success "kiroctl user list --help"
    else
        log_error "kiroctl user list --help"
    fi
    
    log_info "kiroctl user list 실행 중..."
    if $KIROCTL user list > /dev/null 2>&1; then
        log_success "kiroctl user list"
    else
        log_warning "kiroctl user list - AWS 자격 증명 필요"
    fi
    
    # user subscribe
    if $KIROCTL user subscribe --help > /dev/null 2>&1; then
        log_success "kiroctl user subscribe --help"
    else
        log_error "kiroctl user subscribe --help"
    fi
    
    # user unsubscribe
    if $KIROCTL user unsubscribe --help > /dev/null 2>&1; then
        log_success "kiroctl user unsubscribe --help"
    else
        log_error "kiroctl user unsubscribe --help"
    fi
}

# 잘못된 명령어 테스트
test_invalid_commands() {
    print_separator "잘못된 명령어 테스트"
    
    # 존재하지 않는 명령어
    if ! $KIROCTL invalid-command > /dev/null 2>&1; then
        log_success "존재하지 않는 명령어 거부"
    else
        log_error "존재하지 않는 명령어가 실행됨"
    fi
    
    # 잘못된 플래그
    if ! $KIROCTL check --invalid-flag > /dev/null 2>&1; then
        log_success "잘못된 플래그 거부"
    else
        log_error "잘못된 플래그가 허용됨"
    fi
}

# 버전 정보 테스트
test_version() {
    print_separator "버전 정보 테스트"
    
    if $KIROCTL version > /dev/null 2>&1 || $KIROCTL --version > /dev/null 2>&1; then
        log_success "버전 정보 표시"
    else
        log_warning "버전 명령어 미구현"
    fi
}

# 테스트 결과 요약
print_summary() {
    print_separator "테스트 결과 요약"
    
    TOTAL=$((PASSED + FAILED))
    echo "총 테스트: $TOTAL"
    echo -e "${GREEN}성공: $PASSED${NC}"
    echo -e "${RED}실패: $FAILED${NC}"
    echo ""
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ 모든 테스트 통과!${NC}"
        exit 0
    else
        echo -e "${RED}✗ 일부 테스트 실패${NC}"
        exit 1
    fi
}

# 메인 실행
main() {
    echo ""
    echo "======================================"
    echo "  kiroctl 기능 테스트 스크립트"
    echo "======================================"
    echo ""
    
    check_binary
    test_help
    test_check
    test_init
    test_clean
    test_profile
    test_user
    test_invalid_commands
    test_version
    print_summary
}

# 스크립트 실행
main
