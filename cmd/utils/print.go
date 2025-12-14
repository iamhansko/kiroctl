package utils

import (
	"fmt"
	"os"
	"text/tabwriter"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
)

func PrintDebug(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, ColorYellow+"[DEBUG] "+format+ColorReset, args...)
}

func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, ColorRed+"Error: "+format+ColorReset, args...)
}

func PrintSuccess(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, ColorGreen+format+ColorReset, args...)
}

func PrintInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format, args...)
}

func PrintProfileTable(profile Profile) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "Key\tValue")
	fmt.Fprintln(w, "---\t-----")

	fmt.Fprintf(w, "profileName\t%s\n", profile.ProfileName)
	fmt.Fprintf(w, "arn\t%s\n", profile.Arn)
	fmt.Fprintf(w, "status\t%s\n", profile.Status)
	fmt.Fprintf(w, "ssoIdentityDetails.instanceArn\t%s\n", profile.IdentityDetails.SSOIdentityDetails.InstanceArn)
	fmt.Fprintf(w, "ssoIdentityDetails.ssoRegion\t%s\n", profile.IdentityDetails.SSOIdentityDetails.SSORegion)
}

func PrintIdentityStoreUsersTable(users []IdentityStoreUser) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "USER_ID\tMAIL\tUSER_NAME\tDISPLAY_NAME")
	fmt.Fprintln(w, "-------\t----\t---------\t------------")

	for _, user := range users {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", user.UserID, user.Email, user.UserName, user.DisplayName)
	}
}

func PrintSubscriptionsTable(subscriptions []Subscription) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "USER_ID\tSTATUS\tPLAN")
	fmt.Fprintln(w, "-------\t------\t----")

	for _, sub := range subscriptions {
		fmt.Fprintf(w, "%s\t%s\t%s\n", sub.Principal.User, sub.Status, sub.Type.AmazonQ)
	}
}
