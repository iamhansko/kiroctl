package utils

import (
  "bytes"
  "context"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"
  "strings"
  "time"

  "github.com/aws/aws-sdk-go-v2/config"
  "github.com/aws/aws-sdk-go-v2/service/identitystore"
  identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
  "github.com/aws/aws-sdk-go-v2/service/ssoadmin"
)

const (
  DefaultRegion           = "us-east-1"
  SupportedRegionEU       = "eu-central-1"
  DefaultUserAgent        = "aws-sdk-js/2.1692.0 promise"
  DefaultPasswordUserAgent = "aws-sdk-js/2.1467.0 promise"
  DefaultMaxResults       = 1000
  PrincipalTypeUser       = "USER"
  SubscriptionTypePro     = "Q_DEVELOPER_STANDALONE_PRO"
)

type IMDSCredentialsResponse struct {
  Code            string `json:"Code"`
  LastUpdated     string `json:"LastUpdated"`
  Type            string `json:"Type"`
  AccessKeyID     string `json:"AccessKeyId"`
  SecretAccessKey string `json:"SecretAccessKey"`
  Token           string `json:"Token"`
  Expiration      string `json:"Expiration"`
}

type AWSRequestConfig struct {
  Region       string
  Service      string
  Host         string
  Target       string
  UserAgent    string
  RequestBody  []byte
  SessionToken string
}

func HashSHA256(data []byte) string {
  hash := sha256.Sum256(data)
  return hex.EncodeToString(hash[:])
}

func HmacSHA256(key, data []byte) []byte {
  h := hmac.New(sha256.New, key)
  h.Write(data)
  return h.Sum(nil)
}

func GetSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
  kDate := HmacSHA256([]byte("AWS4"+key), []byte(dateStamp))
  kRegion := HmacSHA256(kDate, []byte(regionName))
  kService := HmacSHA256(kRegion, []byte(serviceName))
  kSigning := HmacSHA256(kService, []byte("aws4_request"))
  return kSigning
}

func getCredentialsFromIMDS() (accessKeyID, secretAccessKey, sessionToken string, err error) {
  token, err := getIMDSv2Token()
  if err != nil {
    return "", "", "", fmt.Errorf("failed to get IMDSv2 token: %w", err)
  }

  roleName, err := getIMDSRoleName(token)
  if err != nil {
    return "", "", "", fmt.Errorf("failed to get IAM role name: %w", err)
  }

  credsURL := fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", roleName)
  req, err := http.NewRequest("GET", credsURL, nil)
  if err != nil {
    return "", "", "", fmt.Errorf("failed to create credentials request: %w", err)
  }
  req.Header.Set("X-aws-ec2-metadata-token", token)

  client := &http.Client{Timeout: 5 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return "", "", "", fmt.Errorf("failed to fetch credentials from IMDS: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
    return "", "", "", fmt.Errorf("IMDS returned status %d", resp.StatusCode)
  }

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return "", "", "", fmt.Errorf("failed to read IMDS response: %w", err)
  }

  var imdsResp IMDSCredentialsResponse
  if err := json.Unmarshal(body, &imdsResp); err != nil {
    return "", "", "", fmt.Errorf("failed to parse IMDS credentials: %w", err)
  }

  return imdsResp.AccessKeyID, imdsResp.SecretAccessKey, imdsResp.Token, nil
}

func getIMDSv2Token() (string, error) {
  tokenURL := "http://169.254.169.254/latest/api/token"
  req, err := http.NewRequest("PUT", tokenURL, nil)
  if err != nil {
    return "", fmt.Errorf("failed to create token request: %w", err)
  }
  req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

  client := &http.Client{Timeout: 5 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return "", fmt.Errorf("failed to fetch IMDSv2 token: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
    return "", fmt.Errorf("IMDS token request returned status %d", resp.StatusCode)
  }

  token, err := io.ReadAll(resp.Body)
  if err != nil {
    return "", fmt.Errorf("failed to read token response: %w", err)
  }

  return string(token), nil
}

func getIMDSRoleName(token string) (string, error) {
  roleURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  req, err := http.NewRequest("GET", roleURL, nil)
  if err != nil {
    return "", fmt.Errorf("failed to create role request: %w", err)
  }
  req.Header.Set("X-aws-ec2-metadata-token", token)

  client := &http.Client{Timeout: 5 * time.Second}
  resp, err := client.Do(req)
  if err != nil {
    return "", fmt.Errorf("failed to fetch IAM role name: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
    return "", fmt.Errorf("IMDS role request returned status %d", resp.StatusCode)
  }

  roleName, err := io.ReadAll(resp.Body)
  if err != nil {
    return "", fmt.Errorf("failed to read role name: %w", err)
  }

  return string(roleName), nil
}

func GetAWSCredentials() (accessKeyID, secretAccessKey, sessionToken string, err error) {
  accessKeyID = os.Getenv("AWS_ACCESS_KEY_ID")
  secretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
  sessionToken = os.Getenv("AWS_SESSION_TOKEN")

  if accessKeyID == "" || secretAccessKey == "" {
    return getCredentialsFromIMDS()
  }

  return accessKeyID, secretAccessKey, sessionToken, nil
}

func CreateAWSSignature(config AWSRequestConfig, accessKeyID, secretAccessKey string) (authHeader, payloadHash, amzDate string) {
  now := time.Now().UTC()
  amzDate = now.Format("20060102T150405Z")
  dateStamp := now.Format("20060102")

  payloadHash = HashSHA256(config.RequestBody)

  canonicalURI := "/"
  canonicalQueryString := ""
  canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n", config.Host, payloadHash, amzDate)
  if config.SessionToken != "" {
    canonicalHeaders += fmt.Sprintf("x-amz-security-token:%s\n", config.SessionToken)
  }
  canonicalHeaders += fmt.Sprintf("x-amz-target:%s\nx-amz-user-agent:%s\n", config.Target, config.UserAgent)

  signedHeaders := "host;x-amz-content-sha256;x-amz-date"
  if config.SessionToken != "" {
    signedHeaders += ";x-amz-security-token"
  }
  signedHeaders += ";x-amz-target;x-amz-user-agent"

  canonicalRequest := fmt.Sprintf("POST\n%s\n%s\n%s\n%s\n%s",
    canonicalURI,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  )

  algorithm := "AWS4-HMAC-SHA256"
  credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, config.Region, config.Service)
  stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
    algorithm,
    amzDate,
    credentialScope,
    HashSHA256([]byte(canonicalRequest)),
  )

  signingKey := GetSignatureKey(secretAccessKey, dateStamp, config.Region, config.Service)
  signature := hex.EncodeToString(HmacSHA256(signingKey, []byte(stringToSign)))

  authHeader = fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
    algorithm,
    accessKeyID,
    credentialScope,
    signedHeaders,
    signature,
  )

  return authHeader, payloadHash, amzDate
}

func ExecuteAWSRequest(endpoint string, config AWSRequestConfig, authHeader, payloadHash, amzDate string) error {
  req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return err
  }

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return fmt.Errorf("failed to read response: %w", err)
  }

  fmt.Printf("Status: %s\n", resp.Status)
  fmt.Printf("Response: %s\n", string(body))

  return nil
}

func CreateHTTPRequest(endpoint string, config AWSRequestConfig, authHeader, payloadHash, amzDate string) (*http.Request, error) {
  req, err := http.NewRequest("POST", endpoint, bytes.NewReader(config.RequestBody))
  if err != nil {
    return nil, fmt.Errorf("failed to create request: %w", err)
  }

  req.Header.Set("Content-Type", "application/x-amz-json-1.0")
  req.Header.Set("X-Amz-User-Agent", config.UserAgent)
  req.Header.Set("X-Amz-Target", config.Target)
  req.Header.Set("X-Amz-Content-Sha256", payloadHash)
  req.Header.Set("X-Amz-Date", amzDate)
  if config.SessionToken != "" {
    req.Header.Set("X-Amz-Security-Token", config.SessionToken)
  }
  req.Header.Set("Authorization", authHeader)

  return req, nil
}

func GetRegion(regionFlag string) string {
  region := regionFlag
  if region == "" {
    region = os.Getenv("AWS_DEFAULT_REGION")
  }
  if region == "" {
    region = DefaultRegion
  }
  return region
}

func ValidateRegion(region string) error {
  if region != DefaultRegion && region != SupportedRegionEU {
    return fmt.Errorf("only %s and %s regions supported", DefaultRegion, SupportedRegionEU)
  }
  return nil
}

func GetInstanceInfo(region string) (string, string, error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return "", "", fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := ssoadmin.NewFromConfig(cfg)

  result, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
  if err != nil {
    return "", "", fmt.Errorf("failed to list SSO instances: %w", err)
  }

  if len(result.Instances) == 0 {
    return "", "", fmt.Errorf("no IAM Identity Center instances found in region %s", region)
  }

  instanceArn := *result.Instances[0].InstanceArn
  identityStoreId := *result.Instances[0].IdentityStoreId
  return instanceArn, identityStoreId, nil
}

func ValidateAndPrintRegion(regionFlag string) (string, error) {
  region := GetRegion(regionFlag)

  if err := ValidateRegion(region); err != nil {
    return "", err
  }

  _, _, _, err := GetAWSCredentials()
  if err != nil {
    return "", fmt.Errorf("failed to get AWS credentials: %w", err)
  }

  fmt.Printf("🌎 Region : %s\n", region)

  return region, nil
}

func GetStringValue(s *string) string {
  if s == nil {
    return ""
  }
  return *s
}

func ListIdentityStoreUsers(region string, identityStoreId string) ([]IdentityStoreUser, error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return nil, fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := identitystore.NewFromConfig(cfg)

  var users []IdentityStoreUser
  paginator := identitystore.NewListUsersPaginator(client, &identitystore.ListUsersInput{
    IdentityStoreId: &identityStoreId,
  })

  for paginator.HasMorePages() {
    output, err := paginator.NextPage(ctx)
    if err != nil {
      return nil, fmt.Errorf("failed to list identity store users: %w", err)
    }

    for _, user := range output.Users {
      idUser := IdentityStoreUser{
        UserID:      *user.UserId,
        UserName:    GetStringValue(user.UserName),
        DisplayName: GetStringValue(user.DisplayName),
      }

      for _, email := range user.Emails {
        if email.Primary {
          idUser.Email = GetStringValue(email.Value)
          break
        }
      }
      if idUser.Email == "" && len(user.Emails) > 0 {
        idUser.Email = GetStringValue(user.Emails[0].Value)
      }

      users = append(users, idUser)
    }
  }

  return users, nil
}

func GetOrCreateInstance(region string) (instanceArn string, identityStoreId string, err error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return "", "", fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := ssoadmin.NewFromConfig(cfg)

  result, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
  if err != nil {
    return "", "", fmt.Errorf("failed to list SSO instances: %w", err)
  }

  if len(result.Instances) > 0 {
    instanceArn := *result.Instances[0].InstanceArn
    identityStoreId := *result.Instances[0].IdentityStoreId

    if err := WaitForInstanceReady(ctx, client, instanceArn); err != nil {
      return "", "", err
    }

    return instanceArn, identityStoreId, nil
  }

  createResult, err := client.CreateInstance(ctx, &ssoadmin.CreateInstanceInput{})
  if err != nil {
    return "", "", fmt.Errorf("failed to create IAM Identity Center instance: %w", err)
  }

  if createResult.InstanceArn == nil {
    return "", "", fmt.Errorf("created instance but ARN is nil")
  }

  instanceArn = *createResult.InstanceArn

  maxRetries := 30
  retryDelay := 3 * time.Second

  for i := 0; i < maxRetries; i++ {
    if i > 0 {
      time.Sleep(retryDelay)
    }

    result, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
    if err != nil {
      return "", "", fmt.Errorf("failed to re-query instance list: %w", err)
    }

    if len(result.Instances) > 0 && result.Instances[0].IdentityStoreId != nil {
      identityStoreId = *result.Instances[0].IdentityStoreId

      if err := WaitForInstanceReady(ctx, client, instanceArn); err != nil {
        if i < maxRetries-1 {
          continue
        }
        return "", "", err
      }

      return instanceArn, identityStoreId, nil
    }
  }

  return "", "", fmt.Errorf("created instance but failed to retrieve Identity Store ID. Please try again later")
}

func GetExistingProfile(region, accessKeyID, secretAccessKey, sessionToken string) (*ProfileInfo, error) {
  config := BuildListProfilesConfig(region, sessionToken)
  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return nil, err
  }

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return nil, fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, _ := io.ReadAll(resp.Body)

  if resp.StatusCode == 404 || resp.StatusCode != 200 {
    return nil, nil
  }

  var response ListProfilesResponse
  if err := json.Unmarshal(body, &response); err != nil {
    return nil, nil
  }

  if len(response.Profiles) > 0 {
    profile := response.Profiles[0]
    return &ProfileInfo{
      ProfileName: profile.ProfileName,
      Arn:         profile.Arn,
      Status:      profile.Status,
    }, nil
  }

  return nil, nil
}

func GetExistingSubscription(region, userId, accessKeyID, secretAccessKey, sessionToken string) (*SubscriptionInfo, error) {
  ctx := context.TODO()
  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return nil, fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := ssoadmin.NewFromConfig(cfg)
  result, err := client.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
  if err != nil {
    return nil, fmt.Errorf("failed to list SSO instances: %w", err)
  }

  if len(result.Instances) == 0 {
    return nil, fmt.Errorf("instance not found")
  }

  instanceArn := *result.Instances[0].InstanceArn

  requestBody := ListUserSubscriptionsRequest{
    InstanceArn:        instanceArn,
    MaxResults:         DefaultMaxResults,
    SubscriptionRegion: region,
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return nil, fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := AWSRequestConfig{
    Region:       region,
    Service:      "user-subscriptions",
    Host:         fmt.Sprintf("service.user-subscriptions.%s.amazonaws.com", region),
    Target:       "AWSZornControlPlaneService.ListUserSubscriptions",
    UserAgent:    "aws-sdk-js/1.0.0 ua/2.0",
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return nil, err
  }

  httpClient := &http.Client{}
  resp, err := httpClient.Do(req)
  if err != nil {
    return nil, fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, _ := io.ReadAll(resp.Body)

  if resp.StatusCode == 404 {
    return nil, nil
  }

  if resp.StatusCode != 200 {
    return nil, nil
  }

  var response struct {
    Subscriptions []SubscriptionDetail `json:"subscriptions"`
  }
  if err := json.Unmarshal(body, &response); err != nil {
    return nil, nil
  }

  for _, sub := range response.Subscriptions {
    if sub.Principal.User == userId {
      return &SubscriptionInfo{
        Status: sub.Status,
        Plan:   sub.Type.AmazonQ,
      }, nil
    }
  }

  return nil, nil
}

func GetProfileArn(region string) (string, error) {
  accessKeyID, secretAccessKey, sessionToken, err := GetAWSCredentials()
  if err != nil {
    return "", err
  }

  config := BuildListProfilesConfig(region, sessionToken)
  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return "", err
  }

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return "", fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, err := io.ReadAll(resp.Body)
  if err != nil {
    return "", fmt.Errorf("failed to read response: %w", err)
  }

  if resp.StatusCode != http.StatusOK {
    return "", fmt.Errorf("request failed with status %s: %s", resp.Status, string(body))
  }

  var response ListProfilesResponse
  if err := json.Unmarshal(body, &response); err != nil {
    return "", fmt.Errorf("failed to parse response: %w", err)
  }

  if len(response.Profiles) == 0 {
    return "", fmt.Errorf("no profiles found in region %s", region)
  }

  return response.Profiles[0].Arn, nil
}

func CreateIdentityStoreUser(region, identityStoreId, userName, givenName, familyName, email string) (string, error) {
  ctx := context.TODO()

  cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
  if err != nil {
    return "", fmt.Errorf("failed to load AWS config: %w", err)
  }

  client := identitystore.NewFromConfig(cfg)

  displayName := fmt.Sprintf("%s %s", givenName, familyName)
  emailType := "work"
  primaryEmail := true

  input := &identitystore.CreateUserInput{
    IdentityStoreId: &identityStoreId,
    UserName:        &userName,
    Name: &identitystoretypes.Name{
      GivenName:  &givenName,
      FamilyName: &familyName,
    },
    DisplayName: &displayName,
    Emails: []identitystoretypes.Email{
      {
        Type:    &emailType,
        Value:   &email,
        Primary: primaryEmail,
      },
    },
  }

  result, err := client.CreateUser(ctx, input)
  if err != nil {
    return "", fmt.Errorf("failed to create user: %w", err)
  }

  return *result.UserId, nil
}

func GenerateUserPassword(region, userId string) (string, error) {
  accessKeyID, secretAccessKey, sessionToken, err := GetAWSCredentials()
  if err != nil {
    return "", err
  }

  requestBody := map[string]string{
    "UserId":       userId,
    "PasswordMode": "OTP",
  }

  requestBodyBytes, err := json.Marshal(requestBody)
  if err != nil {
    return "", fmt.Errorf("failed to marshal request body: %w", err)
  }

  config := AWSRequestConfig{
    Region:       region,
    Service:      "userpool",
    Host:         fmt.Sprintf("identitystore.%s.amazonaws.com", region),
    Target:       "SWBUPService.UpdatePassword",
    UserAgent:    DefaultPasswordUserAgent,
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }

  endpoint := fmt.Sprintf("https://%s/", config.Host)
  authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

  req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
  if err != nil {
    return "", err
  }

  client := &http.Client{}
  resp, err := client.Do(req)
  if err != nil {
    return "", fmt.Errorf("failed to execute request: %w", err)
  }
  defer resp.Body.Close()

  body, _ := io.ReadAll(resp.Body)

  if resp.StatusCode >= 200 && resp.StatusCode < 300 {
    var response map[string]interface{}
    if err := json.Unmarshal(body, &response); err != nil {
      return "", fmt.Errorf("failed to parse response: %w", err)
    }

    if password, ok := response["Password"].(string); ok {
      return password, nil
    }

    return "", fmt.Errorf("response does not contain password: %s", string(body))
  }

  return "", fmt.Errorf("failed to generate password (status: %s, response: %s)", resp.Status, string(body))
}

func WaitForInstanceReady(ctx context.Context, client *ssoadmin.Client, instanceArn string) error {
  describeInput := &ssoadmin.DescribeInstanceInput{
    InstanceArn: &instanceArn,
  }

  maxRetries := 20
  retryDelay := 3 * time.Second

  for i := 0; i < maxRetries; i++ {
    if i > 0 {
      time.Sleep(retryDelay)
    }

    describeResult, err := client.DescribeInstance(ctx, describeInput)
    if err != nil {
      if i < 3 {
        continue
      }
      return nil
    }

    if describeResult != nil {
      status := string(describeResult.Status)
      if status == "ACTIVE" {
        return nil
      }
      if status != "" && i < maxRetries-1 {
        continue
      }
    } else {
      if i >= 3 {
        return nil
      }
    }
  }

  return nil
}

func BuildCreateProfileRequest(region, instanceArn string) CreateProfileRequest {
  return CreateProfileRequest{
    ProfileName: fmt.Sprintf("KiroProfile-%s", region),
    ReferenceTrackerConfiguration: ReferenceTrackerConfiguration{
      RecommendationsWithReferences: "ALLOW",
    },
    ActiveFunctionalities: []string{
      "ANALYSIS",
      "CONVERSATIONS",
      "TASK_ASSIST",
      "TRANSFORMATIONS",
      "COMPLETIONS",
    },
    OptInFeatures: OptInFeatures{
      DashboardAnalytics: DashboardAnalytics{
        Toggle: "ON",
      },
    },
    IdentitySource: IdentitySource{
      SSOIdentitySource: SSOIdentitySource{
        InstanceArn: instanceArn,
        SSORegion:   region,
      },
    },
    ClientToken: "",
  }
}

func CreateProfileWithRetry(region, instanceArn, accessKeyID, secretAccessKey, sessionToken string) (bool, error) {
  maxRetries := 10
  retryDelay := 10 * time.Second

  for attempt := 0; attempt < maxRetries; attempt++ {
    if attempt > 0 {
      fmt.Printf("   → Retrying... (%d/%d)\n", attempt, maxRetries-1)
      time.Sleep(retryDelay)
    }

    requestBody := BuildCreateProfileRequest(region, instanceArn)
    requestBody.ClientToken = fmt.Sprintf("%d", time.Now().UnixNano())

    requestBodyBytes, err := json.Marshal(requestBody)
    if err != nil {
      return false, fmt.Errorf("failed to marshal request body: %w", err)
    }

    config := AWSRequestConfig{
      Region:       region,
      Service:      "codewhisperer",
      Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
      Target:       "AWSCodeWhispererService.CreateProfile",
      UserAgent:    DefaultUserAgent,
      RequestBody:  requestBodyBytes,
      SessionToken: sessionToken,
    }

    endpoint := fmt.Sprintf("https://%s/", config.Host)
    authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

    req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
    if err != nil {
      return false, err
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
      return false, fmt.Errorf("failed to execute request: %w", err)
    }

    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()

    if resp.StatusCode == 409 || strings.Contains(string(body), "already exists") {
      return false, nil
    }

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      return true, nil
    }

    if resp.StatusCode == 400 && strings.Contains(string(body), "ConflictException") {
      continue
    }

    return false, fmt.Errorf("failed to create profile (status: %s, response: %s)", resp.Status, string(body))
  }

  return false, fmt.Errorf("failed to create profile: maximum retry count exceeded")
}

func BuildListProfilesConfig(region, sessionToken string) AWSRequestConfig {
  requestBody := map[string]interface{}{}
  requestBodyBytes, _ := json.Marshal(requestBody)

  return AWSRequestConfig{
    Region:       region,
    Service:      "codewhisperer",
    Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
    Target:       "AWSCodeWhispererService.ListProfiles",
    UserAgent:    DefaultUserAgent,
    RequestBody:  requestBodyBytes,
    SessionToken: sessionToken,
  }
}

func CreateSubscriptionWithRetry(region, userId, accessKeyID, secretAccessKey, sessionToken string) error {
  maxRetries := 10
  retryDelay := 5 * time.Second

  for attempt := 0; attempt < maxRetries; attempt++ {
    if attempt > 0 {
      fmt.Printf("   → Retrying... (%d/%d)\n", attempt, maxRetries-1)
      time.Sleep(retryDelay)
    }

    requestBody := UserSubscribeRequest{
      PrincipalID:      userId,
      PrincipalType:    PrincipalTypeUser,
      SubscriptionType: SubscriptionTypePro,
    }

    requestBodyBytes, err := json.Marshal(requestBody)
    if err != nil {
      return fmt.Errorf("failed to marshal request body: %w", err)
    }

    config := AWSRequestConfig{
      Region:       region,
      Service:      "q",
      Host:         fmt.Sprintf("codewhisperer.%s.amazonaws.com", region),
      Target:       "AmazonQDeveloperService.CreateAssignment",
      UserAgent:    DefaultUserAgent,
      RequestBody:  requestBodyBytes,
      SessionToken: sessionToken,
    }

    endpoint := fmt.Sprintf("https://%s/", config.Host)
    authHeader, payloadHash, amzDate := CreateAWSSignature(config, accessKeyID, secretAccessKey)

    req, err := CreateHTTPRequest(endpoint, config, authHeader, payloadHash, amzDate)
    if err != nil {
      return err
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
      return fmt.Errorf("failed to execute request: %w", err)
    }

    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()

    if resp.StatusCode == 409 || strings.Contains(string(body), "already exists") || strings.Contains(string(body), "already assigned") {
      return nil
    }

    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
      return nil
    }

    if resp.StatusCode == 400 && strings.Contains(string(body), "ResourceNotFoundException") {
      continue
    }

    return fmt.Errorf("failed to configure subscription (status: %s, response: %s)", resp.Status, string(body))
  }

  return fmt.Errorf("failed to configure subscription: maximum retry count exceeded")
}
