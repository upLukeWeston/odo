package component

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/klog"

	"github.com/openshift/odo/pkg/catalog"
	"github.com/openshift/odo/pkg/component"
	"github.com/openshift/odo/pkg/config"
	"github.com/openshift/odo/pkg/devfile"
	"github.com/openshift/odo/pkg/devfile/parser/data/common"
	"github.com/openshift/odo/pkg/envinfo"
	"github.com/openshift/odo/pkg/kclient"
	"github.com/openshift/odo/pkg/log"
	"github.com/openshift/odo/pkg/machineoutput"
	appCmd "github.com/openshift/odo/pkg/odo/cli/application"
	catalogutil "github.com/openshift/odo/pkg/odo/cli/catalog/util"
	"github.com/openshift/odo/pkg/odo/cli/component/ui"
	projectCmd "github.com/openshift/odo/pkg/odo/cli/project"
	commonui "github.com/openshift/odo/pkg/odo/cli/ui"
	"github.com/openshift/odo/pkg/odo/genericclioptions"
	odoutil "github.com/openshift/odo/pkg/odo/util"
	"github.com/openshift/odo/pkg/odo/util/completion"
	"github.com/openshift/odo/pkg/odo/util/experimental"
	"github.com/openshift/odo/pkg/odo/util/pushtarget"
	"github.com/openshift/odo/pkg/util"

	corev1 "k8s.io/api/core/v1"
	ktemplates "k8s.io/kubectl/pkg/util/templates"
)

// CreateOptions encapsulates create options
type CreateOptions struct {
	componentSettings config.ComponentSettings
	componentBinary   string
	componentGit      string
	componentGitRef   string
	componentContext  string
	componentPorts    []string
	componentEnvVars  []string
	memoryMax         string
	memoryMin         string
	memory            string
	cpuMax            string
	cpuMin            string
	cpu               string
	interactive       bool
	now               bool
	*CommonPushOptions
	devfileMetadata DevfileMetadata
}

// DevfileMetadata includes devfile component metadata
type DevfileMetadata struct {
	componentType      string
	componentName      string
	componentNamespace string
	devfileSupport     bool
	devfileLink        string
	devfileRegistry    catalog.Registry
	downloadSource     string
}

// CreateRecommendedCommandName is the recommended watch command name
const CreateRecommendedCommandName = "create"

// LocalDirectoryDefaultLocation is the default location of where --local files should always be..
// since the application will always be in the same directory as `.odo`, we will always set this as: ./
const LocalDirectoryDefaultLocation = "./"

// Constants for devfile component
const devFile = "devfile.yaml"
const envFile = ".odo/env/env.yaml"

// DevfilePath is the path of devfile.yaml, the default path is "./devfile.yaml"
var DevfilePath = filepath.Join(LocalDirectoryDefaultLocation, devFile)

// EnvFilePath is the path of env.yaml for devfile component, the defult path is "./.odo/env/env.yaml"
var EnvFilePath = filepath.Join(LocalDirectoryDefaultLocation, envFile)

// ConfigFilePath is the default path of config.yaml for s2i component
const ConfigFilePath = "./.odo/config.yaml"

var createLongDesc = ktemplates.LongDesc(`Create a configuration describing a component.

If a component name is not provided, it'll be auto-generated.

A full list of component types that can be deployed is available using: 'odo catalog list'

By default, builder images (component type) will be used from the current namespace. You can explicitly supply a namespace by using: odo create namespace/name:version
If version is not specified by default, latest will be chosen as the version.`)

var createExample = ktemplates.Examples(`  # Create new Node.js component with the source in current directory.
%[1]s nodejs

# Create new Node.js component named 'frontend' with the source in './frontend' directory
%[1]s nodejs frontend --context ./frontend

# Create new Java component with binary named sample.jar in './target' directory
%[1]s java:8  --binary target/sample.jar

# Create new Node.js component with source from remote git repository
%[1]s nodejs --git https://github.com/openshift/nodejs-ex.git

# Create new Node.js component with custom ports, additional environment variables and memory and cpu limits
%[1]s nodejs --port 8080,8100/tcp,9100/udp --env key=value,key1=value1 --memory 4Gi --cpu 2

# Create new Node.js component and download the sample project named nodejs-web-app
%[1]s nodejs --downloadSource=nodejs-web-app`)

const defaultProjectName = "devfile-project-name"

// NewCreateOptions returns new instance of CreateOptions
func NewCreateOptions() *CreateOptions {
	return &CreateOptions{
		CommonPushOptions: NewCommonPushOptions(),
	}
}

func (co *CreateOptions) setComponentSourceAttributes() (err error) {

	// Set the correct application context
	co.componentSettings.Application = &(co.Context.Application)

	// By default we set the source as LOCAL (if --local, --binary or --git isn't passed)
	componentSourceType := config.LOCAL

	// If --local, --binary or --git is passed, let's set the correct source type.
	if len(co.componentBinary) != 0 {
		componentSourceType = config.BINARY
	} else if len(co.componentGit) != 0 {
		componentSourceType = config.GIT
	}
	co.componentSettings.SourceType = &componentSourceType

	// Here we set the correct source path for each type
	switch componentSourceType {

	// --binary
	case config.BINARY:
		// Convert componentContext to absolute path, so it can be safely used in filepath.Rel
		// even when it is not set (empty). In this case filepath.Abs will return current directory.
		absContext, err := filepath.Abs(co.componentContext)
		if err != nil {
			return err
		}
		absPath, err := filepath.Abs(co.componentBinary)
		if err != nil {
			return err
		}
		// we need to store the SourceLocation relative to the componentContext
		relativePathToSource, err := filepath.Rel(absContext, absPath)
		if err != nil {
			return err
		}
		co.componentSettings.SourceLocation = &relativePathToSource

	// --git
	case config.GIT:
		co.componentSettings.SourceLocation = &(co.componentGit)
		componentSourceType = config.GIT
		co.componentSettings.SourceType = &componentSourceType

	// --local / default
	case config.LOCAL:

		directory := LocalDirectoryDefaultLocation
		co.componentSettings.SourceLocation = &directory

	// Error out by default if no type of sources were passed..
	default:
		return fmt.Errorf("The source can be either --binary or --local or --git")

	}

	// Set the Git reference if passed
	if len(co.componentGitRef) != 0 {
		co.componentSettings.Ref = &(co.componentGitRef)
	}

	// Error out if reference is passed but no --git flag passed
	if len(co.componentGit) == 0 && len(co.componentGitRef) != 0 {
		return fmt.Errorf("The --ref flag is only valid for --git flag")
	}

	return
}

func (co *CreateOptions) setComponentName(args []string) (err error) {
	componentImageName, componentType, _, _ := util.ParseComponentImageName(args[0])
	co.componentSettings.Type = &componentImageName

	if len(args) == 2 {
		co.componentSettings.Name = &args[1]
		return
	}

	if co.componentSettings.SourceType == nil {
		return errors.Wrap(err, "component type is mandatory parameter to generate a default component name")
	}

	componentName, err := createDefaultComponentName(
		co.Context,
		componentType,
		*(co.componentSettings.SourceType),
		co.componentContext,
	)
	if err != nil {
		return err
	}

	co.componentSettings.Name = &componentName
	return
}

func getSourceLocation(componentContext string, currentDirectory string) (string, error) {

	// After getting the path relative to the current directory, we set the SourceLocation
	sourceLocation, err := filepath.Rel(currentDirectory, componentContext)
	if err != nil {
		return "", errors.Wrapf(err, "unable to get a path relative to the current directory")
	}

	// If the paths are the same (currentDirectory vs co.componentSettings.SourceLocation)
	// then we use the default location
	if sourceLocation == "." {
		return LocalDirectoryDefaultLocation, nil
	}

	return sourceLocation, nil
}

func createDefaultComponentName(context *genericclioptions.Context, componentType string, sourceType config.SrcType, sourcePath string) (string, error) {
	// Retrieve the componentName, if the componentName isn't specified, we will use the default image name
	var err error
	finalSourcePath := sourcePath
	// we only get absolute path for local source type
	if sourceType == config.LOCAL {
		if sourcePath == "" {
			wd, err := os.Getwd()
			if err != nil {
				return "", err
			}
			finalSourcePath = wd
		} else {
			finalSourcePath, err = filepath.Abs(sourcePath)
			if err != nil {
				return "", err
			}
		}
	}

	componentName, err := component.GetDefaultComponentName(
		finalSourcePath,
		sourceType,
		componentType,
		component.ComponentList{},
	)

	if err != nil {
		return "", nil
	}

	return componentName, nil
}

func (co *CreateOptions) setResourceLimits() error {
	ensureAndLogProperResourceUsage(co.memory, co.memoryMin, co.memoryMax, "memory")

	ensureAndLogProperResourceUsage(co.cpu, co.cpuMin, co.cpuMax, "cpu")

	memoryQuantity, err := util.FetchResourceQuantity(corev1.ResourceMemory, co.memoryMin, co.memoryMax, co.memory)
	if err != nil {
		return err
	}
	if memoryQuantity != nil {
		minMemory := memoryQuantity.MinQty.String()
		maxMemory := memoryQuantity.MaxQty.String()
		co.componentSettings.MinMemory = &minMemory
		co.componentSettings.MaxMemory = &maxMemory
	}

	cpuQuantity, err := util.FetchResourceQuantity(corev1.ResourceCPU, co.cpuMin, co.cpuMax, co.cpu)
	if err != nil {
		return err
	}
	if cpuQuantity != nil {
		minCPU := cpuQuantity.MinQty.String()
		maxCPU := cpuQuantity.MaxQty.String()
		co.componentSettings.MinCPU = &minCPU
		co.componentSettings.MaxCPU = &maxCPU
	}

	return nil
}

// Complete completes create args
func (co *CreateOptions) Complete(name string, cmd *cobra.Command, args []string) (err error) {

	if experimental.IsExperimentalModeEnabled() {
		// Add a disclaimer that we are in *experimental mode*
		log.Experimental("Experimental mode is enabled, use at your own risk")

		if util.CheckPathExists(ConfigFilePath) {
			return errors.New("This directory already contains a component")
		}

		if len(args) == 0 {
			co.interactive = true
		}

		// Default namespace setup
		var defaultComponentNamespace string
		// If the push target is set to Docker, we can't assume we have an active Kube context
		if !pushtarget.IsPushTargetDocker() {
			// Get current active namespace
			client, err := kclient.New()
			if err != nil {
				return err
			}
			defaultComponentNamespace = client.Namespace
		}

		// Configure the context
		if len(co.componentContext) != 0 {
			DevfilePath = filepath.Join(co.componentContext, devFile)
			EnvFilePath = filepath.Join(co.componentContext, envFile)
			co.CommonPushOptions.componentContext = co.componentContext
		}

		catalogDevfileList, err := catalog.ListDevfileComponents(co.devfileMetadata.devfileRegistry.Name)
		if err != nil {
			return err
		}
		if catalogDevfileList.DevfileRegistries == nil {
			log.Warning("Please run `odo registry add <registry name> <registry URL>` to add a registry then create a devfile components\n")
		}

		var componentType string
		var componentName string
		var componentNamespace string

		if co.interactive {
			// Interactive mode
			// Get component type, name and namespace from user's choice via interactive mode

			// devfile.yaml is not present, user has to specify the component type
			// Component type: We provide supported devfile component list then let you choose
			if !util.CheckPathExists(DevfilePath) {
				var supDevfileCatalogList []catalog.DevfileComponentType
				for _, devfileComponent := range catalogDevfileList.Items {
					if devfileComponent.Support {
						supDevfileCatalogList = append(supDevfileCatalogList, devfileComponent)
					}
				}
				componentType = ui.SelectDevfileComponentType(supDevfileCatalogList)
			}

			// Component name: User needs to specify the componet name, by default it is component type that user chooses
			componentName = ui.EnterDevfileComponentName(componentType)

			// Component namespace: User needs to specify component namespace,
			// by default it is the current active namespace if it can't get from --project flag or --namespace flag
			if len(co.devfileMetadata.componentNamespace) == 0 {
				if cmd.Flags().Changed("project") {
					componentNamespace, err = cmd.Flags().GetString("project")
					if err != nil {
						return err
					}
				} else {
					componentNamespace = ui.EnterDevfileComponentNamespace(defaultComponentNamespace)
				}
			} else {
				componentNamespace = co.devfileMetadata.componentNamespace
			}
		} else {
			// Direct mode (User enters the full command)
			// Get component type, name and namespace from user's full command

			if util.CheckPathExists(DevfilePath) {
				return errors.New("This directory already contains a devfile.yaml, please delete it and run the component creation command again")
			}

			// Component type: Get from full command's first argument (mandatory in direct mode)
			componentType = args[0]

			// Component name: Get from full command's second argument (optional in direct mode), by default it is component type from first argument
			if len(args) == 2 {
				componentName = args[1]
			} else {
				componentName = args[0]
			}

			// Component namespace: Get from --project flag or --namespace flag, by default it is the current active namespace
			if len(co.devfileMetadata.componentNamespace) == 0 {
				if cmd.Flags().Changed("project") {
					componentNamespace, err = cmd.Flags().GetString("project")
					if err != nil {
						return err
					}
				} else {
					componentNamespace = defaultComponentNamespace
				}
			} else {
				componentNamespace = co.devfileMetadata.componentNamespace
			}
		}

		// Set devfileMetadata struct
		co.devfileMetadata.componentType = componentType
		co.devfileMetadata.componentName = strings.ToLower(componentName)
		co.devfileMetadata.componentNamespace = strings.ToLower(componentNamespace)

		// If devfile.yaml is present, we don't need to download the devfile.yaml later
		if util.CheckPathExists(DevfilePath) {
			co.devfileMetadata.devfileSupport = true

			err = co.InitEnvInfoFromContext()
			if err != nil {
				return err
			}

			return nil
		}

		// Categorize the sections
		log.Info("Validation")

		// Since we need to support both devfile and s2i, so we have to check if the component type is
		// supported by devfile, if it is supported we return and will download the corresponding devfile.yaml later,
		// but if it is not supported we still need to run all codes related with s2i
		spinner := log.Spinner("Checking devfile compatibility")

		for _, devfileComponent := range catalogDevfileList.Items {
			if co.devfileMetadata.componentType == devfileComponent.Name && devfileComponent.Support {
				co.devfileMetadata.devfileSupport = true
				co.devfileMetadata.devfileLink = devfileComponent.Link
				co.devfileMetadata.devfileRegistry = devfileComponent.Registry
			}
		}

		registrySpinner := log.Spinnerf("Creating a devfile component from registry: %s", co.devfileMetadata.devfileRegistry.Name)

		if co.devfileMetadata.devfileSupport {
			err = co.InitEnvInfoFromContext()
			if err != nil {
				return err
			}

			spinner.End(true)
			registrySpinner.End(true)
			return nil
		}

		spinner.End(false)
		registrySpinner.End(false)
		log.Italic("\nPlease run `odo catalog list components` for a list of supported devfile component types")
	}

	if len(args) == 0 || !cmd.HasFlags() {
		co.interactive = true
	}

	// this populates the LocalConfigInfo as well
	co.Context = genericclioptions.NewContextCreatingAppIfNeeded(cmd)
	if err != nil {
		return errors.Wrap(err, "failed intiating local config")
	}

	// Do not execute S2I specific code on Kubernetes Cluster
	// return from here, if it is not an openshift cluster.
	openshiftCluster, _ := co.Client.IsImageStreamSupported()
	if !openshiftCluster {
		return errors.New("component not found")
	}

	// check to see if config file exists or not, if it does that
	// means we shouldn't allow the user to override the current component
	if co.LocalConfigInfo.ConfigFileExists() {
		return errors.New("this directory already contains a component")
	}

	co.componentSettings = co.LocalConfigInfo.GetComponentSettings()

	co.Context = genericclioptions.NewContextCreatingAppIfNeeded(cmd)

	// Below code is for INTERACTIVE mode
	if co.interactive {
		client := co.Client

		catalogList, err := catalog.ListComponents(client)
		if err != nil {
			return err
		}

		componentTypeCandidates := catalogutil.FilterHiddenComponents(catalogList.Items)
		selectedComponentType := ui.SelectComponentType(componentTypeCandidates)
		selectedImageTag := ui.SelectImageTag(componentTypeCandidates, selectedComponentType)
		componentType := selectedComponentType + ":" + selectedImageTag
		co.componentSettings.Type = &componentType

		// Ask for the type of source if not provided
		selectedSourceType := ui.SelectSourceType([]config.SrcType{config.LOCAL, config.GIT, config.BINARY})
		co.componentSettings.SourceType = &selectedSourceType
		selectedSourcePath := LocalDirectoryDefaultLocation

		// Get the current directory
		currentDirectory, err := os.Getwd()
		if err != nil {
			return err
		}

		if selectedSourceType == config.BINARY {

			// We ask for the source of the component context
			co.componentContext = ui.EnterInputTypePath("context", currentDirectory, ".")
			klog.V(4).Infof("Context: %s", co.componentContext)

			// If it's a binary, we have to ask where the actual binary in relation
			// to the context
			selectedSourcePath = ui.EnterInputTypePath("binary", ".")

			// Get the correct source location
			sourceLocation, err := getSourceLocation(selectedSourcePath, co.componentContext)
			if err != nil {
				return errors.Wrapf(err, "unable to get source location")
			}
			co.componentSettings.SourceLocation = &sourceLocation

		} else if selectedSourceType == config.GIT {

			// For git, we ask for the Git URL and set that as the source location
			cmpSrcLOC, selectedGitRef := ui.EnterGitInfo()
			co.componentSettings.SourceLocation = &cmpSrcLOC
			co.componentSettings.Ref = &selectedGitRef

		} else if selectedSourceType == config.LOCAL {

			// We ask for the source of the component, in this case the "path"!
			co.componentContext = ui.EnterInputTypePath("path", currentDirectory, ".")

			// Get the correct source location
			if co.componentContext == "" {
				co.componentContext = LocalDirectoryDefaultLocation
			}
			co.componentSettings.SourceLocation = &co.componentContext

		}

		defaultComponentName, err := createDefaultComponentName(co.Context, selectedComponentType, selectedSourceType, selectedSourcePath)
		if err != nil {
			return err
		}
		componentName := ui.EnterComponentName(defaultComponentName, co.Context)

		appName := ui.EnterOpenshiftName(co.Context.Application, "Which application do you want the commponent to be associated with", co.Context)
		co.componentSettings.Application = &appName

		projectName := ui.EnterOpenshiftName(co.Context.Project, "Which project go you want the component to be created in", co.Context)
		co.componentSettings.Project = &projectName

		co.componentSettings.Name = &componentName

		var ports []string

		if commonui.Proceed("Do you wish to set advanced options") {
			// if the user doesn't opt for advanced options, ports field would remain unpopulated
			// we then set it at the end of this function
			ports = ui.EnterPorts()

			co.componentEnvVars = ui.EnterEnvVars()

			if commonui.Proceed("Do you wish to set resource limits") {
				memMax := ui.EnterMemory("maximum", "512Mi")
				memMin := ui.EnterMemory("minimum", memMax)
				cpuMax := ui.EnterCPU("maximum", "1")
				cpuMin := ui.EnterCPU("minimum", cpuMax)

				memoryQuantity, err := util.FetchResourceQuantity(corev1.ResourceMemory, memMin, memMax, "")
				if err != nil {
					return err
				}
				if memoryQuantity != nil {
					co.componentSettings.MinMemory = &memMin
					co.componentSettings.MaxMemory = &memMax
				}
				cpuQuantity, err := util.FetchResourceQuantity(corev1.ResourceCPU, cpuMin, cpuMax, "")
				if err != nil {
					return err
				}
				if cpuQuantity != nil {
					co.componentSettings.MinCPU = &cpuMin
					co.componentSettings.MaxCPU = &cpuMax
				}
			}
		}

		// if user didn't opt for advanced options, "ports" value remains empty which panics the "odo push"
		// so we set the ports here
		if len(ports) == 0 {
			ports, err = co.Client.GetPortsFromBuilderImage(*co.componentSettings.Type)
			if err != nil {
				return err
			}
		}

		co.componentSettings.Ports = &ports
		// Above code is for INTERACTIVE mode

	} else {
		// Else if NOT using interactive / UI
		err = co.setComponentSourceAttributes()
		if err != nil {
			return err
		}
		err = co.setComponentName(args)
		if err != nil {
			return err
		}
		err = co.setResourceLimits()
		if err != nil {
			return err
		}

		var portList []string
		if len(co.componentPorts) > 0 {
			portList = co.componentPorts
		} else {
			portList, err = co.Client.GetPortsFromBuilderImage(*co.componentSettings.Type)
			if err != nil {
				return err
			}
		}

		co.componentSettings.Ports = &(portList)
	}

	co.componentSettings.Project = &(co.Context.Project)
	envs, err := config.NewEnvVarListFromSlice(co.componentEnvVars)
	if err != nil {
		return
	}
	co.componentSettings.Envs = envs
	co.ignores = []string{}
	if co.now {
		co.ResolveSrcAndConfigFlags()
		err = co.ResolveProject(co.Context.Project)
		if err != nil {
			return err
		}
	}
	return
}

// Validate validates the create parameters
func (co *CreateOptions) Validate() (err error) {

	if experimental.IsExperimentalModeEnabled() {
		if co.devfileMetadata.devfileSupport {
			// Validate if the devfile component that user wants to create already exists
			spinner := log.Spinner("Validating devfile component")
			defer spinner.End(false)

			if util.CheckPathExists(EnvFilePath) {
				return errors.New("This workspace directory already contains a devfile component")
			}

			err = util.ValidateK8sResourceName("component name", co.devfileMetadata.componentName)
			if err != nil {
				return err
			}

			// Only validate namespace if pushtarget isn't docker
			if !pushtarget.IsPushTargetDocker() {
				err := util.ValidateK8sResourceName("component namespace", co.devfileMetadata.componentNamespace)
				if err != nil {
					return err
				}
			}

			spinner.End(true)

			return nil
		}
	}

	log.Info("Validation")

	supported, err := catalog.IsComponentTypeSupported(co.Context.Client, *co.componentSettings.Type)
	if err != nil {
		return err
	}

	if !supported {
		log.Infof("Warning: %s is not fully supported by odo, and it is not guaranteed to work", *co.componentSettings.Type)
	}

	s := log.Spinner("Validating component")
	defer s.End(false)
	if err := component.ValidateComponentCreateRequest(co.Context.Client, co.componentSettings, co.componentContext); err != nil {
		return err
	}

	s.End(true)
	return nil
}

// Downloads first project from list of projects in devfile
// Currenty type git with a non github url is not supported
func (co *CreateOptions) downloadProject(projectPassed string) error {
	var project common.DevfileProject
	devObj, err := devfile.Parse(DevfilePath)
	if err != nil {
		return err
	}
	projects := devObj.Data.GetProjects()
	nOfProjects := len(projects)
	if nOfProjects == 0 {
		return errors.Errorf("No project found in devfile component.")
	}

	if nOfProjects == 1 && projectPassed == defaultProjectName {
		project = projects[0]
	} else if nOfProjects > 1 && projectPassed == defaultProjectName {
		project = projects[0]
		log.Warning("There are multiple projects in this devfile but none have been specified in --downloadSource. Downloading the first: " + project.Name)
	} else { //If the user has specified a project
		projectFound := false
		for indexOfProject, projectInfo := range projects {
			if projectInfo.Name == projectPassed { //Get the index
				project = projects[indexOfProject]
				projectFound = true
			}
		}

		if !projectFound {
			return errors.Errorf("The project: %s specified in --downloadSource does not exist", projectPassed)
		}
	}

	path, err := os.Getwd()
	if err != nil {
		return errors.Wrapf(err, "Could not get the current working directory.")
	}

	if project.ClonePath != "" {
		clonePath := project.ClonePath
		if runtime.GOOS == "windows" {
			clonePath = strings.Replace(clonePath, "\\", "/", -1)
		}

		path = filepath.Join(path, clonePath)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			err = os.MkdirAll(path, os.FileMode(0755))
			if err != nil {
				return errors.Wrap(err, "Failed creating folder with path: "+path)
			}
		}
	}

	err = util.IsValidProjectDir(path, DevfilePath)
	if err != nil {
		return err
	}

	var url, sparseDir string
	if project.Git != nil {
		if strings.Contains(project.Git.Location, "github.com") {
			url, err = util.GetGitHubZipURL(project.Git.Location)
			if err != nil {
				return err
			}
			sparseDir = project.Git.SparseCheckoutDir
		} else {
			return errors.Errorf("Project type git with non github url not supported")
		}
	} else if project.Github != nil {
		url, err = util.GetGitHubZipURL(project.Github.Location)
		if err != nil {
			return err
		}
		sparseDir = project.Github.SparseCheckoutDir
	} else if project.Zip != nil {
		url = project.Zip.Location
		sparseDir = project.Github.SparseCheckoutDir
	} else {
		return errors.Errorf("Project type not supported")
	}

	err = checkoutProject(sparseDir, url, path)

	if err != nil {
		return err
	}

	return nil
}

// Run has the logic to perform the required actions as part of command
func (co *CreateOptions) Run() (err error) {
	if experimental.IsExperimentalModeEnabled() {
		// Download devfile.yaml file and create env.yaml file
		if co.devfileMetadata.devfileSupport {
			if !util.CheckPathExists(DevfilePath) {
				err := util.DownloadFile(co.devfileMetadata.devfileRegistry.URL+co.devfileMetadata.devfileLink, DevfilePath)
				if err != nil {
					return errors.Wrap(err, "Faile to download devfile.yaml for devfile component")
				}
			}

			if util.CheckPathExists(DevfilePath) && co.devfileMetadata.downloadSource != "" {
				err = co.downloadProject(co.devfileMetadata.downloadSource)
				if err != nil {
					return errors.Wrap(err, "Failed to download project for devfile component")
				}
			}

			err := co.EnvSpecificInfo.SetConfiguration("create", envinfo.ComponentSettings{Name: co.devfileMetadata.componentName, Namespace: co.devfileMetadata.componentNamespace})
			if err != nil {
				return errors.Wrap(err, "Failed to create env.yaml for devfile component")
			}

			log.Italic("\nPlease use `odo push` command to create the component with source deployed")
			return nil
		}
	}

	err = co.LocalConfigInfo.SetComponentSettings(co.componentSettings)
	if err != nil {
		return errors.Wrapf(err, "failed to persist the component settings to config file")
	}
	if co.now {
		co.Context, co.LocalConfigInfo, err = genericclioptions.UpdatedContext(co.Context)

		if err != nil {
			return errors.Wrap(err, "unable to retrieve updated local config")
		}
		err = co.SetSourceInfo()
		if err != nil {
			return errors.Wrap(err, "unable to set source information")
		}
		err = co.Push()
		if err != nil {
			return errors.Wrapf(err, "failed to push the changes")
		}
	} else {
		log.Italic("\nPlease use `odo push` command to create the component with source deployed")
	}
	if log.IsJSON() {
		var componentDesc component.Component
		co.Context, co.LocalConfigInfo, err = genericclioptions.UpdatedContext(co.Context)
		if err != nil {
			return err
		}
		state := component.GetComponentState(co.Client, *co.componentSettings.Name, co.Context.Application)

		if state == component.StateTypeNotPushed || state == component.StateTypeUnknown {
			componentDesc, err = component.GetComponentFromConfig(co.LocalConfigInfo)
			componentDesc.Status.State = state
			if err != nil {
				return err
			}
		} else {
			componentDesc, err = component.GetComponent(co.Context.Client, *co.componentSettings.Name, co.Context.Application, co.Context.Project)
			if err != nil {
				return err
			}
		}

		componentDesc.Spec.Ports = co.LocalConfigInfo.GetPorts()
		machineoutput.OutputSuccess(componentDesc)
	}
	return
}

// The general cpu/memory is used as a fallback when it's set and both min-cpu/memory max-cpu/memory are not set
// when the only thing specified is the min or max value, we exit the application
func ensureAndLogProperResourceUsage(resource, resourceMin, resourceMax, resourceName string) {
	if strings.HasPrefix(resourceMin, "-") {
		log.Errorf("min-%s cannot be negative", resource)
		os.Exit(1)
	}
	if strings.HasPrefix(resourceMax, "-") {
		log.Errorf("max-%s cannot be negative", resource)
		os.Exit(1)
	}
	if strings.HasPrefix(resource, "-") {
		log.Errorf("%s cannot be negative", resource)
		os.Exit(1)
	}
	if resourceMin != "" && resourceMax != "" && resource != "" {
		log.Infof("`--%s` will be ignored as `--min-%s` and `--max-%s` has been passed\n", resourceName, resourceName, resourceName)
	}
	if (resourceMin == "") != (resourceMax == "") && resource != "" {
		log.Infof("Using `--%s` %s for min and max limits.\n", resourceName, resource)
	}
	if (resourceMin == "") != (resourceMax == "") && resource == "" {
		log.Errorf("`--min-%s` should accompany `--max-%s` or pass `--%s` to use same value for both min and max or try not passing any of them\n", resourceName, resourceName, resourceName)
		os.Exit(1)
	}
}

func checkoutProject(sparseCheckoutDir, zipURL, path string) error {

	if sparseCheckoutDir != "" {
		err := util.GetAndExtractZip(zipURL, path, sparseCheckoutDir)
		if err != nil {
			return errors.Wrap(err, "failed to download and extract project zip folder")
		}
	} else {
		// extract project to current working directory
		err := util.GetAndExtractZip(zipURL, path, "/")
		if err != nil {
			return errors.Wrap(err, "failed to download and extract project zip folder")
		}
	}
	return nil
}

// NewCmdCreate implements the create odo command
func NewCmdCreate(name, fullName string) *cobra.Command {
	co := NewCreateOptions()
	var componentCreateCmd = &cobra.Command{
		Use:         fmt.Sprintf("%s <component_type> [component_name] [flags]", name),
		Short:       "Create a new component",
		Long:        createLongDesc,
		Example:     fmt.Sprintf(createExample, fullName),
		Args:        cobra.RangeArgs(0, 2),
		Annotations: map[string]string{"machineoutput": "json", "command": "component"},
		Run: func(cmd *cobra.Command, args []string) {
			genericclioptions.GenericRun(co, cmd, args)
		},
	}
	componentCreateCmd.Flags().StringVarP(&co.componentBinary, "binary", "b", "", "Create a binary file component component using given artifact. Works only with Java components. File needs to be in the context directory.")
	componentCreateCmd.Flags().StringVarP(&co.componentGit, "git", "g", "", "Create a git component using this repository.")
	componentCreateCmd.Flags().StringVarP(&co.componentGitRef, "ref", "r", "", "Use a specific ref e.g. commit, branch or tag of the git repository")
	genericclioptions.AddContextFlag(componentCreateCmd, &co.componentContext)
	componentCreateCmd.Flags().StringVar(&co.memory, "memory", "", "Amount of memory to be allocated to the component. ex. 100Mi (sets min-memory and max-memory to this value)")
	componentCreateCmd.Flags().StringVar(&co.memoryMin, "min-memory", "", "Limit minimum amount of memory to be allocated to the component. ex. 100Mi")
	componentCreateCmd.Flags().StringVar(&co.memoryMax, "max-memory", "", "Limit maximum amount of memory to be allocated to the component. ex. 100Mi")
	componentCreateCmd.Flags().StringVar(&co.cpu, "cpu", "", "Amount of cpu to be allocated to the component. ex. 100m or 0.1 (sets min-cpu and max-cpu to this value)")
	componentCreateCmd.Flags().StringVar(&co.cpuMin, "min-cpu", "", "Limit minimum amount of cpu to be allocated to the component. ex. 100m")
	componentCreateCmd.Flags().StringVar(&co.cpuMax, "max-cpu", "", "Limit maximum amount of cpu to be allocated to the component. ex. 1")
	componentCreateCmd.Flags().StringSliceVarP(&co.componentPorts, "port", "p", []string{}, "Ports to be used when the component is created (ex. 8080,8100/tcp,9100/udp)")
	componentCreateCmd.Flags().StringSliceVar(&co.componentEnvVars, "env", []string{}, "Environmental variables for the component. For example --env VariableName=Value")

	if experimental.IsExperimentalModeEnabled() {
		componentCreateCmd.Flags().StringVar(&co.devfileMetadata.downloadSource, "downloadSource", "", "Download sample project from devfile.")
		componentCreateCmd.Flags().Lookup("downloadSource").NoOptDefVal = defaultProjectName //Default value to pass to the flag if one is not specified.
		componentCreateCmd.Flags().StringVar(&co.devfileMetadata.devfileRegistry.Name, "registry", "", "Create devfile component from specific registry")
	}

	componentCreateCmd.SetUsageTemplate(odoutil.CmdUsageTemplate)

	// Adding `--now` flag
	genericclioptions.AddNowFlag(componentCreateCmd, &co.now)
	//Adding `--project` flag
	projectCmd.AddProjectFlag(componentCreateCmd)
	//Adding `--application` flag
	appCmd.AddApplicationFlag(componentCreateCmd)

	completion.RegisterCommandHandler(componentCreateCmd, completion.CreateCompletionHandler)
	completion.RegisterCommandFlagHandler(componentCreateCmd, "context", completion.FileCompletionHandler)
	completion.RegisterCommandFlagHandler(componentCreateCmd, "binary", completion.FileCompletionHandler)

	return componentCreateCmd
}
