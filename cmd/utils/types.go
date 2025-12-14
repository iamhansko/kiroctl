package utils

type Subscription struct {
	Principal Principal        `json:"principal"`
	Status    string           `json:"status"`
	Type      SubscriptionType `json:"type"`
}

type Principal struct {
	User string `json:"user"`
}

type SubscriptionType struct {
	AmazonQ string `json:"amazonQ"`
}

type IdentityStoreUser struct {
	UserID      string
	UserName    string
	DisplayName string
	Email       string
}

type Profile struct {
	ProfileName     string          `json:"profileName"`
	Arn             string          `json:"arn"`
	Status          string          `json:"status"`
	IdentityDetails IdentityDetails `json:"identityDetails"`
}

type IdentityDetails struct {
	SSOIdentityDetails SSOIdentityDetails `json:"ssoIdentityDetails"`
}

type SSOIdentityDetails struct {
	InstanceArn string `json:"instanceArn"`
	SSORegion   string `json:"ssoRegion"`
}

type ListUserSubscriptionsRequest struct {
	InstanceArn        string `json:"instanceArn"`
	MaxResults         int    `json:"maxResults"`
	SubscriptionRegion string `json:"subscriptionRegion"`
}

type ListUserSubscriptionsResponse struct {
	Subscriptions []Subscription `json:"subscriptions"`
}

type UserSubscribeRequest struct {
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	SubscriptionType string `json:"subscriptionType"`
}

type UserUnsubscribeRequest struct {
	PrincipalID   string `json:"principalId"`
	PrincipalType string `json:"principalType"`
}

type ListProfilesRequest struct{}

type ListProfilesResponse struct {
	Profiles []Profile `json:"profiles"`
}

type ProfileInfo struct {
	ProfileName string `json:"profileName"`
	Arn         string `json:"arn"`
	Status      string `json:"status"`
}

type SubscriptionInfo struct {
	Status string
	Plan   string
}

type CreateProfileRequest struct {
	ProfileName                   string                        `json:"profileName"`
	ReferenceTrackerConfiguration ReferenceTrackerConfiguration `json:"referenceTrackerConfiguration"`
	ActiveFunctionalities         []string                      `json:"activeFunctionalities"`
	OptInFeatures                 OptInFeatures                 `json:"optInFeatures"`
	IdentitySource                IdentitySource                `json:"identitySource"`
	ClientToken                   string                        `json:"clientToken"`
}

type ReferenceTrackerConfiguration struct {
	RecommendationsWithReferences string `json:"recommendationsWithReferences"`
}

type OptInFeatures struct {
	DashboardAnalytics DashboardAnalytics `json:"dashboardAnalytics"`
}

type DashboardAnalytics struct {
	Toggle string `json:"toggle"`
}

type IdentitySource struct {
	SSOIdentitySource SSOIdentitySource `json:"ssoIdentitySource"`
}

type SSOIdentitySource struct {
	InstanceArn string `json:"instanceArn"`
	SSORegion   string `json:"ssoRegion"`
}

type DeleteProfileRequest struct {
	ProfileArn string `json:"profileArn"`
}

type SubscriptionDetail struct {
	Principal PrincipalInfo        `json:"principal"`
	Status    string               `json:"status"`
	Type      SubscriptionTypeInfo `json:"type"`
}

type PrincipalInfo struct {
	User string `json:"user"`
}

type SubscriptionTypeInfo struct {
	AmazonQ string `json:"amazonQ"`
}
