package url

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/openshift/odo/pkg/envinfo"

	"github.com/openshift/odo/pkg/odo/util/pushtarget"

	"github.com/openshift/odo/pkg/odo/util/experimental"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/odo/pkg/config"
	"github.com/openshift/odo/pkg/lclient"
	"github.com/openshift/odo/pkg/log"
	"github.com/openshift/odo/pkg/machineoutput"
	"github.com/openshift/odo/pkg/odo/genericclioptions"
	"github.com/openshift/odo/pkg/odo/util"
	"github.com/openshift/odo/pkg/odo/util/completion"
	"github.com/openshift/odo/pkg/url"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	ktemplates "k8s.io/kubectl/pkg/util/templates"
)

const listRecommendedCommandName = "list"

var (
	urlListShortDesc = `List URLs`
	urlListLongDesc  = ktemplates.LongDesc(`Lists all the available URLs which can be used to access the components.`)
	urlListExample   = ktemplates.Examples(` # List the available URLs
  %[1]s
	`)
)

// URLListOptions encapsulates the options for the odo url list command
type URLListOptions struct {
	componentContext string
	*genericclioptions.Context
}

// NewURLListOptions creates a new URLCreateOptions instance
func NewURLListOptions() *URLListOptions {
	return &URLListOptions{}
}

// Complete completes URLListOptions after they've been Listed
func (o *URLListOptions) Complete(name string, cmd *cobra.Command, args []string) (err error) {
	if experimental.IsExperimentalModeEnabled() {
		o.Context = genericclioptions.NewDevfileContext(cmd)
		o.EnvSpecificInfo, err = envinfo.NewEnvSpecificInfo(o.componentContext)
	} else {
		o.Context = genericclioptions.NewContext(cmd)
		o.LocalConfigInfo, err = config.NewLocalConfigInfo(o.componentContext)
	}
	if err != nil {
		return errors.Wrap(err, "failed intiating local config")
	}
	return
}

// Validate validates the URLListOptions based on completed values
func (o *URLListOptions) Validate() (err error) {
	return util.CheckOutputFlag(o.OutputFlag)
}

// Run contains the logic for the odo url list command
func (o *URLListOptions) Run() (err error) {
	if experimental.IsExperimentalModeEnabled() {
		if pushtarget.IsPushTargetDocker() {
			componentName := o.EnvSpecificInfo.GetName()
			client, err := lclient.New()
			if err != nil {
				return err
			}
			urls, err := url.ListDockerURL(client, componentName, o.EnvSpecificInfo)
			if err != nil {
				return err
			}
			if log.IsJSON() {
				machineoutput.OutputSuccess(urls)
			} else {
				if len(urls.Items) == 0 {
					return fmt.Errorf("no URLs found for component %v", componentName)
				}

				log.Infof("Found the following URLs for component %v", componentName)
				tabWriterURL := tabwriter.NewWriter(os.Stdout, 5, 2, 3, ' ', tabwriter.TabIndent)
				fmt.Fprintln(tabWriterURL, "NAME", "\t", "STATE", "\t", "URL", "\t", "PORT")

				// are there changes between local and container states?
				outOfSync := false
				for _, u := range urls.Items {
					var urlString string
					if u.Status.State == url.StateTypeNotPushed {
						// to be consistent with URL for ingress and routes
						// if not pushed, display URl as ://
						urlString = "://"
					} else {
						urlString = fmt.Sprintf("%s:%s", u.Spec.Host, strconv.Itoa(u.Spec.ExternalPort))
					}
					fmt.Fprintln(tabWriterURL, u.Name, "\t", u.Status.State, "\t", urlString, "\t", u.Spec.Port)
					if u.Status.State != url.StateTypePushed {
						outOfSync = true
					}
				}
				tabWriterURL.Flush()
				if outOfSync {
					log.Info("There are local changes. Please run 'odo push'.")
				}
			}
		} else {
			componentName := o.EnvSpecificInfo.GetName()
			urls, err := url.ListIngressURL(o.KClient, o.EnvSpecificInfo, componentName)
			if err != nil {
				return err
			}
			if log.IsJSON() {
				machineoutput.OutputSuccess(urls)
			} else {
				if len(urls.Items) == 0 {
					return fmt.Errorf("no URLs found for component %v", componentName)
				}
				log.Infof("Found the following URLs for component %v", componentName)
				tabWriterURL := tabwriter.NewWriter(os.Stdout, 5, 2, 3, ' ', tabwriter.TabIndent)
				fmt.Fprintln(tabWriterURL, "NAME", "\t", "STATE", "\t", "URL", "\t", "PORT", "\t", "SECURE")

				// are there changes between local and cluster states?
				outOfSync := false
				for _, u := range urls.Items {
					fmt.Fprintln(tabWriterURL, u.Name, "\t", u.Status.State, "\t", url.GetURLString(url.GetProtocol(routev1.Route{}, url.ConvertIngressURLToIngress(u, componentName), experimental.IsExperimentalModeEnabled()), "", u.Spec.Host, experimental.IsExperimentalModeEnabled()), "\t", u.Spec.Port, "\t", u.Spec.Secure)
					if u.Status.State != url.StateTypePushed {
						outOfSync = true
					}
				}

				tabWriterURL.Flush()
				if outOfSync {
					log.Info("There are local changes. Please run 'odo push'.")
				}
			}
		}
	} else {
		urls, err := url.List(o.Client, o.LocalConfigInfo, o.Component(), o.Application)
		if err != nil {
			return err
		}
		if log.IsJSON() {
			machineoutput.OutputSuccess(urls)
		} else {
			if len(urls.Items) == 0 {
				return fmt.Errorf("no URLs found for component %v in application %v", o.Component(), o.Application)
			}

			log.Infof("Found the following URLs for component %v in application %v:", o.Component(), o.Application)
			tabWriterURL := tabwriter.NewWriter(os.Stdout, 5, 2, 3, ' ', tabwriter.TabIndent)
			fmt.Fprintln(tabWriterURL, "NAME", "\t", "STATE", "\t", "URL", "\t", "PORT", "\t", "SECURE")

			// are there changes between local and cluster states?
			outOfSync := false
			for _, u := range urls.Items {
				fmt.Fprintln(tabWriterURL, u.Name, "\t", u.Status.State, "\t", url.GetURLString(u.Spec.Protocol, u.Spec.Host, "", experimental.IsExperimentalModeEnabled()), "\t", u.Spec.Port, "\t", u.Spec.Secure)
				if u.Status.State != url.StateTypePushed {
					outOfSync = true
				}
			}
			tabWriterURL.Flush()
			if outOfSync {
				log.Info("There are local changes. Please run 'odo push'.")
			}
		}
	}

	return
}

// NewCmdURLList implements the odo url list command.
func NewCmdURLList(name, fullName string) *cobra.Command {
	o := NewURLListOptions()
	urlListCmd := &cobra.Command{
		Use:         name,
		Short:       urlListShortDesc,
		Long:        urlListLongDesc,
		Example:     fmt.Sprintf(urlListExample, fullName),
		Args:        cobra.NoArgs,
		Annotations: map[string]string{"machineoutput": "json"},
		Run: func(cmd *cobra.Command, args []string) {
			genericclioptions.GenericRun(o, cmd, args)
		},
	}
	genericclioptions.AddContextFlag(urlListCmd, &o.componentContext)
	completion.RegisterCommandFlagHandler(urlListCmd, "context", completion.FileCompletionHandler)

	return urlListCmd
}
