package component

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	devfileParser "github.com/openshift/odo/pkg/devfile/parser"
	"github.com/openshift/odo/pkg/envinfo"
	"github.com/openshift/odo/pkg/log"
	projectCmd "github.com/openshift/odo/pkg/odo/cli/project"
	"github.com/openshift/odo/pkg/odo/genericclioptions"
	"github.com/openshift/odo/pkg/odo/util/completion"
	"github.com/openshift/odo/pkg/odo/util/experimental"
	"github.com/openshift/odo/pkg/util"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	odoutil "github.com/openshift/odo/pkg/odo/util"

	ktemplates "k8s.io/kubectl/pkg/util/templates"
)

// TODO: add CLI Reference doc
var deployCmdExample = ktemplates.Examples(`  # Deploys an image and deploys the application 
%[1]s
  `)

// DeployRecommendedCommandName is the recommended build command name
const DeployRecommendedCommandName = "deploy"

// DeployOptions encapsulates options that build command uses
type DeployOptions struct {
	*CommonPushOptions

	// devfile path
	DevfilePath     string
	DockerfileURL   string
	DockerfileBytes []byte
	namespace       string
	tag             string
	ManifestSource  []byte
}

// NewDeployOptions returns new instance of BuildOptions
// with "default" values for certain values, for example, show is "false"
func NewDeployOptions() *DeployOptions {
	return &DeployOptions{
		CommonPushOptions: NewCommonPushOptions(),
	}
}

// Complete completes push args
func (do *DeployOptions) Complete(name string, cmd *cobra.Command, args []string) (err error) {
	do.DevfilePath = filepath.Join(do.componentContext, do.DevfilePath)
	envInfo, err := envinfo.NewEnvSpecificInfo(do.componentContext)
	if err != nil {
		return errors.Wrap(err, "unable to retrieve configuration information")
	}
	do.EnvSpecificInfo = envInfo
	do.Context = genericclioptions.NewDevfileContext(cmd)

	return nil
}

// Validate validates the push parameters
func (do *DeployOptions) Validate() (err error) {
	var splitTag = strings.Split(do.tag, "/")
	if len(splitTag) != 3 {
		return errors.New("invalid tag: odo deploy reguires a tag in the format <registry>/namespace>/<image>")
	}

	characterMatch := regexp.MustCompile(`[a-zA-Z0-9\.\-:]*`)

	for _, element := range splitTag {
		elementMatch := characterMatch.MatchString(element)
		if !elementMatch {
			return errors.New("invalid tag: " + element + " in the tag contains an illegal character. It must only contain alphanumerical values, periods, colons, and dashes.")
		}
		if strings.HasSuffix(element, ".") || strings.HasSuffix(element, "-") || strings.HasSuffix(element, ":") {
			return errors.New("invalid tag: " + element + " in the tag has an invalid final character. It must end in an alphanumeric value.")
		}
	}

	return
}

// Run has the logic to perform the required actions as part of command
func (do *DeployOptions) Run() (err error) {
	devObj, err := devfileParser.Parse(do.DevfilePath)
	if err != nil {
		return err
	}
	metadata := devObj.Data.GetMetadata()
	dockerfileURL := metadata.Dockerfile
	localDir, err := os.Getwd()
	if err != nil {
		return err
	}

	manifestURL := metadata.Manifest
	do.ManifestSource, err = util.DownloadFileInMemory(manifestURL)
	if err != nil {
		return errors.Wrap(err, "Unable to download manifest "+manifestURL)
	}

	//Download Dockerfile to .odo, build, then delete from .odo dir
	//If Dockerfile is present in the project already, use that for the build
	//If Dockerfile is present in the project and field is in devfile, build the one already in the project and warn the user.
	if dockerfileURL != "" && util.CheckPathExists(filepath.Join(localDir, "Dockerfile")) {
		// TODO: make clearer more visible output
		log.Warning("Dockerfile already exists in project directory and one is specified in Devfile.")
		log.Warningf("Using Dockerfile specified in devfile from '%s'", dockerfileURL)
	}

	if !util.CheckPathExists(filepath.Join(localDir, ".odo")) {
		return errors.Wrap(err, ".odo folder not found")
	}

	if dockerfileURL != "" {
		dockerfileBytes, err := util.DownloadFileInMemory(dockerfileURL)
		if err != nil {
			return errors.New("unable to download Dockerfile from URL specified in devfile")
		}
		do.DockerfileURL = dockerfileURL
		do.DockerfileBytes = dockerfileBytes

		dockerfileStrings := strings.Split(string(dockerfileBytes), "\n")
		for _, line := range dockerfileStrings {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "FROM") {
				break
			}
			return errors.Errorf("%s does not point to a valid Dockerfile", dockerfileURL)
		}

	} else if !util.CheckPathExists(filepath.Join(localDir, "Dockerfile")) {
		return errors.New("dockerfile required for build. No 'dockerfile' field found in devfile, or Dockerfile found in project directory")
	}

	err = do.DevfileBuild()
	if err != nil {
		return err
	}

	err = do.DevfileDeploy()
	if err != nil {
		return err
	}

	return nil
}

// NewCmdDeploy implements the push odo command
func NewCmdDeploy(name, fullName string) *cobra.Command {
	do := NewDeployOptions()

	var deployCmd = &cobra.Command{
		Use:         fmt.Sprintf("%s [component name]", name),
		Short:       "Deploy image for component",
		Long:        `Deploy image for component`,
		Example:     fmt.Sprintf(deployCmdExample, fullName),
		Args:        cobra.MaximumNArgs(1),
		Annotations: map[string]string{"command": "component"},
		Run: func(cmd *cobra.Command, args []string) {
			genericclioptions.GenericRun(do, cmd, args)
		},
	}
	genericclioptions.AddContextFlag(deployCmd, &do.componentContext)

	// enable devfile flag if experimental mode is enabled
	if experimental.IsExperimentalModeEnabled() {
		deployCmd.Flags().StringVar(&do.DevfilePath, "devfile", "./devfile.yaml", "Path to a devfile.yaml")
		deployCmd.Flags().StringVar(&do.tag, "tag", "", "Tag used to build the image")
	}

	//Adding `--project` flag
	projectCmd.AddProjectFlag(deployCmd)

	deployCmd.SetUsageTemplate(odoutil.CmdUsageTemplate)
	completion.RegisterCommandHandler(deployCmd, completion.ComponentNameCompletionHandler)
	completion.RegisterCommandFlagHandler(deployCmd, "context", completion.FileCompletionHandler)

	return deployCmd
}
