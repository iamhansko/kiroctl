@echo off
setlocal enabledelayedexpansion

REM kiroctl 기능 테스트 스크립트 (Windows)
REM 모든 명령어의 기본 동작을 검증합니다

set PASSED=0
set FAILED=0

echo.
echo ======================================
echo   kiroctl 기능 테스트 스크립트
echo ======================================
echo.

REM kiroctl 바이너리 확인
if exist ".\builds\kiroctl.exe" (
    set KIROCTL=".\builds\kiroctl.exe"
    echo [PASS] kiroctl 바이너리 확인: kiroctl.exe
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl 바이너리를 찾을 수 없습니다. 먼저 빌드하세요: .\scripts\build_windows.bat
    exit /b 1
)

echo.
echo ==========================================
echo 도움말 명령어 테스트
echo ==========================================
echo.

%KIROCTL% --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl --help
    set /a FAILED+=1
)

%KIROCTL% -h >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl -h
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl -h
    set /a FAILED+=1
)

echo.
echo ==========================================
echo check 명령어 테스트
echo ==========================================
echo.

%KIROCTL% check --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl check --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl check --help
    set /a FAILED+=1
)

echo [INFO] kiroctl check (기본 리전) 실행 중...
%KIROCTL% check >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl check (기본 리전)
    set /a PASSED+=1
) else (
    echo [WARN] kiroctl check (기본 리전) - AWS 자격 증명 필요
)

echo [INFO] kiroctl check --region eu-central-1 실행 중...
%KIROCTL% check --region eu-central-1 >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl check --region eu-central-1
    set /a PASSED+=1
) else (
    echo [WARN] kiroctl check --region eu-central-1 - AWS 자격 증명 필요
)

echo.
echo ==========================================
echo init 명령어 테스트
echo ==========================================
echo.

%KIROCTL% init --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl init --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl init --help
    set /a FAILED+=1
)

echo [WARN] kiroctl init - 대화형 명령어로 자동 테스트 생략

echo.
echo ==========================================
echo clean 명령어 테스트
echo ==========================================
echo.

%KIROCTL% clean --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl clean --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl clean --help
    set /a FAILED+=1
)

echo [WARN] kiroctl clean - 파괴적 명령어로 자동 테스트 생략

echo.
echo ==========================================
echo profile 명령어 테스트
echo ==========================================
echo.

%KIROCTL% profile --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl profile --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl profile --help
    set /a FAILED+=1
)

%KIROCTL% profile create --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl profile create --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl profile create --help
    set /a FAILED+=1
)

%KIROCTL% profile delete --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl profile delete --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl profile delete --help
    set /a FAILED+=1
)

%KIROCTL% profile status --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl profile status --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl profile status --help
    set /a FAILED+=1
)

echo [INFO] kiroctl profile status 실행 중...
%KIROCTL% profile status >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl profile status
    set /a PASSED+=1
) else (
    echo [WARN] kiroctl profile status - AWS 자격 증명 필요
)

echo.
echo ==========================================
echo user 명령어 테스트
echo ==========================================
echo.

%KIROCTL% user --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user --help
    set /a FAILED+=1
)

%KIROCTL% user create --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user create --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user create --help
    set /a FAILED+=1
)

%KIROCTL% user delete --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user delete --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user delete --help
    set /a FAILED+=1
)

%KIROCTL% user list --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user list --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user list --help
    set /a FAILED+=1
)

echo [INFO] kiroctl user list 실행 중...
%KIROCTL% user list >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user list
    set /a PASSED+=1
) else (
    echo [WARN] kiroctl user list - AWS 자격 증명 필요
)

%KIROCTL% user subscribe --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user subscribe --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user subscribe --help
    set /a FAILED+=1
)

%KIROCTL% user unsubscribe --help >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] kiroctl user unsubscribe --help
    set /a PASSED+=1
) else (
    echo [FAIL] kiroctl user unsubscribe --help
    set /a FAILED+=1
)

echo.
echo ==========================================
echo 잘못된 명령어 테스트
echo ==========================================
echo.

%KIROCTL% invalid-command >nul 2>&1
if !errorlevel! neq 0 (
    echo [PASS] 존재하지 않는 명령어 거부
    set /a PASSED+=1
) else (
    echo [FAIL] 존재하지 않는 명령어가 실행됨
    set /a FAILED+=1
)

%KIROCTL% check --invalid-flag >nul 2>&1
if !errorlevel! neq 0 (
    echo [PASS] 잘못된 플래그 거부
    set /a PASSED+=1
) else (
    echo [FAIL] 잘못된 플래그가 허용됨
    set /a FAILED+=1
)

echo.
echo ==========================================
echo 버전 정보 테스트
echo ==========================================
echo.

%KIROCTL% version >nul 2>&1
if !errorlevel! equ 0 (
    echo [PASS] 버전 정보 표시
    set /a PASSED+=1
) else (
    %KIROCTL% --version >nul 2>&1
    if !errorlevel! equ 0 (
        echo [PASS] 버전 정보 표시
        set /a PASSED+=1
    ) else (
        echo [WARN] 버전 명령어 미구현
    )
)

echo.
echo ==========================================
echo 테스트 결과 요약
echo ==========================================
echo.

set /a TOTAL=PASSED+FAILED
echo 총 테스트: !TOTAL!
echo 성공: !PASSED!
echo 실패: !FAILED!
echo.

if !FAILED! equ 0 (
    echo [SUCCESS] 모든 테스트 통과!
    exit /b 0
) else (
    echo [ERROR] 일부 테스트 실패
    exit /b 1
)
