package component

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/fatih/color"
	"github.com/golang/glog"
	"github.com/openshift/odo/pkg/component"
	"github.com/openshift/odo/pkg/config"
	"github.com/openshift/odo/pkg/devfile/adapters/common"
	"github.com/openshift/odo/pkg/devfile/adapters/kubernetes/storage"
	"github.com/openshift/odo/pkg/devfile/adapters/kubernetes/utils"

	"github.com/openshift/odo/pkg/exec"

	versionsCommon "github.com/openshift/odo/pkg/devfile/parser/data/common"
	"github.com/openshift/odo/pkg/kclient"
	"github.com/openshift/odo/pkg/log"
	odoutil "github.com/openshift/odo/pkg/odo/util"
	"github.com/openshift/odo/pkg/sync"
	"github.com/openshift/odo/pkg/util"
	"github.com/pkg/errors"
)

// New instantiantes a component adapter
func New(adapterContext common.AdapterContext, client kclient.Client) Adapter {
	return Adapter{
		Client:         client,
		AdapterContext: adapterContext,
	}
}

// Adapter is a component adapter implementation for Kubernetes
type Adapter struct {
	Client kclient.Client
	common.AdapterContext
	devfileInitCmd  string
	devfileBuildCmd string
	devfileRunCmd   string
}

// Push updates the component if a matching component exists or creates one if it doesn't exist
// Once the component has started, it will sync the source code to it.
func (a Adapter) Push(parameters common.PushParameters) (err error) {
	componentExists := utils.ComponentExists(a.Client, a.ComponentName)
	globExps := util.GetAbsGlobExps(parameters.Path, parameters.IgnoredFiles)

	a.devfileInitCmd = parameters.DevfileInitCmd
	a.devfileBuildCmd = parameters.DevfileBuildCmd
	a.devfileRunCmd = parameters.DevfileRunCmd

	deletedFiles := []string{}
	changedFiles := []string{}
	isForcePush := false
	podChanged := false
	runInit := true
	var podName string

	// If the component already exists, retrieve the pod's name before it's potentially updated
	if componentExists {
		pod, err := a.waitAndGetComponentPod(true)
		if err != nil {
			return errors.Wrapf(err, "unable to get pod for component %s", a.ComponentName)
		}
		podName = pod.GetName()
		runInit = false
	}

	// Validate the devfile build and run commands
	pushDevfileCommands, err := common.ValidateAndGetPushDevfileCommands(a.Devfile.Data, a.devfileInitCmd, a.devfileBuildCmd, a.devfileRunCmd)
	if err != nil {
		return errors.Wrap(err, "failed to validate devfile build and run commands")
	}

	err = a.createOrUpdateComponent(componentExists)
	if err != nil {
		return errors.Wrap(err, "unable to create or update component")
	}

	_, err = a.Client.WaitForDeploymentRollout(a.ComponentName)
	if err != nil {
		return errors.Wrap(err, "error while waiting for deployment rollout")
	}

	// Wait for Pod to be in running state otherwise we can't sync data or exec commands to it.
	pod, err := a.waitAndGetComponentPod(false)
	if err != nil {
		return errors.Wrapf(err, "unable to get pod for component %s", a.ComponentName)
	}

	err = component.ApplyConfig(nil, &a.Client, config.LocalConfigInfo{}, parameters.EnvSpecificInfo, color.Output, componentExists)
	if err != nil {
		odoutil.LogErrorAndExit(err, "Failed to update config to component deployed.")
	}

	// Compare the name of the pod with the one before the rollout. If they differ, it means there's a new pod and a force push is required
	if componentExists && podName != pod.GetName() {
		podChanged = true
	}

	// Sync source code to the component
	// If syncing for the first time, sync the entire source directory
	// If syncing to an already running component, sync the deltas
	// If syncing from an odo watch process, skip this step, as we already have the list of changed and deleted files.
	if !podChanged && !parameters.ForceBuild && len(parameters.WatchFiles) == 0 && len(parameters.WatchDeletedFiles) == 0 {
		absIgnoreRules := util.GetAbsGlobExps(parameters.Path, parameters.IgnoredFiles)

		spinner := log.NewStatus(log.GetStdout())
		defer spinner.End(true)
		if componentExists {
			spinner.Start("Checking file changes for pushing", false)
		} else {
			// if the component doesn't exist, we don't check for changes in the files
			// thus we show a different message
			spinner.Start("Checking files for pushing", false)
		}

		// Before running the indexer, make sure the .odo folder exists (or else the index file will not get created)
		odoFolder := filepath.Join(parameters.Path, ".odo")
		if _, err := os.Stat(odoFolder); os.IsNotExist(err) {
			err = os.Mkdir(odoFolder, 0750)
			if err != nil {
				return errors.Wrap(err, "unable to create directory")
			}
		}

		// run the indexer and find the modified/added/deleted/renamed files
		filesChanged, filesDeleted, err := util.RunIndexer(parameters.Path, absIgnoreRules)
		spinner.End(true)

		if err != nil {
			return errors.Wrap(err, "unable to run indexer")
		}

		// If the component already exists, sync only the files that changed
		if componentExists {
			// apply the glob rules from the .gitignore/.odo file
			// and ignore the files on which the rules apply and filter them out
			filesChangedFiltered, filesDeletedFiltered := util.FilterIgnores(filesChanged, filesDeleted, absIgnoreRules)

			// Remove the relative file directory from the list of deleted files
			// in order to make the changes correctly within the Kubernetes pod
			deletedFiles, err = util.RemoveRelativePathFromFiles(filesDeletedFiltered, parameters.Path)
			if err != nil {
				return errors.Wrap(err, "unable to remove relative path from list of changed/deleted files")
			}
			glog.V(4).Infof("List of files to be deleted: +%v", deletedFiles)
			changedFiles = filesChangedFiltered

			if len(filesChangedFiltered) == 0 && len(filesDeletedFiltered) == 0 {
				// no file was modified/added/deleted/renamed, thus return without building
				log.Success("No file changes detected, skipping build. Use the '-f' flag to force the build.")
				return nil
			}
		}
	} else if len(parameters.WatchFiles) > 0 || len(parameters.WatchDeletedFiles) > 0 {
		changedFiles = parameters.WatchFiles
		deletedFiles = parameters.WatchDeletedFiles
	}

	if parameters.ForceBuild || !componentExists || podChanged {
		isForcePush = true
	}

	// Sync the local source code to the component
	err = a.pushLocal(parameters.Path,
		changedFiles,
		deletedFiles,
		isForcePush,
		globExps,
		pod.GetName(),
		pod.Spec.Containers,
	)
	if err != nil {
		return errors.Wrapf(err, "Failed to sync to component with name %s", a.ComponentName)
	}

	err = a.execDevfile(pushDevfileCommands, componentExists, parameters.Show, pod.GetName(), pod.Spec.Containers, runInit)
	if err != nil {
		return err
	}

	return nil
}

// DoesComponentExist returns true if a component with the specified name exists, false otherwise
func (a Adapter) DoesComponentExist(cmpName string) bool {
	return utils.ComponentExists(a.Client, cmpName)
}

func (a Adapter) createOrUpdateComponent(componentExists bool) (err error) {
	componentName := a.ComponentName

	labels := map[string]string{
		"component": componentName,
	}

	containers, err := utils.GetContainers(a.Devfile)
	if err != nil {
		return err
	}

	if len(containers) == 0 {
		return fmt.Errorf("No valid components found in the devfile")
	}

	containers, err = utils.UpdateContainersWithSupervisord(a.Devfile, containers, a.devfileRunCmd)
	if err != nil {
		return err
	}

	objectMeta := kclient.CreateObjectMeta(componentName, a.Client.Namespace, labels, nil)
	podTemplateSpec := kclient.GeneratePodTemplateSpec(objectMeta, containers)

	kclient.AddBootstrapSupervisordInitContainer(podTemplateSpec)

	componentAliasToVolumes := utils.GetVolumes(a.Devfile)

	var uniqueStorages []common.Storage
	volumeNameToPVCName := make(map[string]string)
	processedVolumes := make(map[string]bool)

	// Get a list of all the unique volume names and generate their PVC names
	for _, volumes := range componentAliasToVolumes {
		for _, vol := range volumes {
			if _, ok := processedVolumes[*vol.Name]; !ok {
				processedVolumes[*vol.Name] = true

				// Generate the PVC Names
				glog.V(3).Infof("Generating PVC name for %v", *vol.Name)
				generatedPVCName, err := storage.GeneratePVCNameFromDevfileVol(*vol.Name, componentName)
				if err != nil {
					return err
				}

				// Check if we have an existing PVC with the labels, overwrite the generated name with the existing name if present
				existingPVCName, err := storage.GetExistingPVC(&a.Client, *vol.Name, componentName)
				if err != nil {
					return err
				}
				if len(existingPVCName) > 0 {
					glog.V(3).Infof("Found an existing PVC for %v, PVC %v will be re-used", *vol.Name, existingPVCName)
					generatedPVCName = existingPVCName
				}

				pvc := common.Storage{
					Name:   generatedPVCName,
					Volume: vol,
				}
				uniqueStorages = append(uniqueStorages, pvc)
				volumeNameToPVCName[*vol.Name] = generatedPVCName
			}
		}
	}

	// Add PVC and Volume Mounts to the podTemplateSpec
	err = kclient.AddPVCAndVolumeMount(podTemplateSpec, volumeNameToPVCName, componentAliasToVolumes)
	if err != nil {
		return err
	}

	deploymentSpec := kclient.GenerateDeploymentSpec(*podTemplateSpec)
	var containerPorts []corev1.ContainerPort
	for _, c := range deploymentSpec.Template.Spec.Containers {
		if len(containerPorts) == 0 {
			containerPorts = c.Ports
		} else {
			containerPorts = append(containerPorts, c.Ports...)
		}
	}
	serviceSpec := kclient.GenerateServiceSpec(objectMeta.Name, containerPorts)
	glog.V(3).Infof("Creating deployment %v", deploymentSpec.Template.GetName())
	glog.V(3).Infof("The component name is %v", componentName)

	if utils.ComponentExists(a.Client, componentName) {
		// If the component already exists, get the resource version of the deploy before updating
		glog.V(3).Info("The component already exists, attempting to update it")
		deployment, err := a.Client.UpdateDeployment(*deploymentSpec)
		if err != nil {
			return err
		}
		glog.V(3).Infof("Successfully updated component %v", componentName)
		oldSvc, err := a.Client.KubeClient.CoreV1().Services(a.Client.Namespace).Get(componentName, metav1.GetOptions{})
		objectMetaTemp := objectMeta
		ownerReference := kclient.GenerateOwnerReference(deployment)
		objectMetaTemp.OwnerReferences = append(objectMeta.OwnerReferences, ownerReference)
		if err != nil {
			// no old service was found, create a new one
			if len(serviceSpec.Ports) > 0 {
				_, err = a.Client.CreateService(objectMetaTemp, *serviceSpec)
				if err != nil {
					return err
				}
				glog.V(3).Infof("Successfully created Service for component %s", componentName)
			}
		} else {
			if len(serviceSpec.Ports) > 0 {
				serviceSpec.ClusterIP = oldSvc.Spec.ClusterIP
				objectMetaTemp.ResourceVersion = oldSvc.GetResourceVersion()
				_, err = a.Client.UpdateService(objectMetaTemp, *serviceSpec)
				if err != nil {
					return err
				}
				glog.V(3).Infof("Successfully update Service for component %s", componentName)
			} else {
				err = a.Client.KubeClient.CoreV1().Services(a.Client.Namespace).Delete(componentName, &metav1.DeleteOptions{})
				if err != nil {
					return err
				}
			}
		}
	} else {
		deployment, err := a.Client.CreateDeployment(*deploymentSpec)
		if err != nil {
			return err
		}
		glog.V(3).Infof("Successfully created component %v", componentName)
		ownerReference := kclient.GenerateOwnerReference(deployment)
		objectMetaTemp := objectMeta
		objectMetaTemp.OwnerReferences = append(objectMeta.OwnerReferences, ownerReference)
		if len(serviceSpec.Ports) > 0 {
			_, err = a.Client.CreateService(objectMetaTemp, *serviceSpec)
			if err != nil {
				return err
			}
			glog.V(3).Infof("Successfully created Service for component %s", componentName)
		}

	}

	// Get the storage adapter and create the volumes if it does not exist
	stoAdapter := storage.New(a.AdapterContext, a.Client)
	err = stoAdapter.Create(uniqueStorages)
	if err != nil {
		return err
	}

	return nil
}

// pushLocal syncs source code from the user's disk to the component
func (a Adapter) pushLocal(path string, files []string, delFiles []string, isForcePush bool, globExps []string, podName string, containers []corev1.Container) error {
	glog.V(4).Infof("Push: componentName: %s, path: %s, files: %s, delFiles: %s, isForcePush: %+v", a.ComponentName, path, files, delFiles, isForcePush)

	// Edge case: check to see that the path is NOT empty.
	emptyDir, err := util.IsEmpty(path)
	if err != nil {
		return errors.Wrapf(err, "Unable to check directory: %s", path)
	} else if emptyDir {
		return errors.New(fmt.Sprintf("Directory / file %s is empty", path))
	}

	// Find at least one pod with the source volume mounted, error out if none can be found
	containerName, err := getFirstContainerWithSourceVolume(containers)
	if err != nil {
		return errors.Wrapf(err, "error while retrieving container from pod: %s", podName)
	}

	// Sync the files to the pod
	s := log.Spinner("Syncing files to the component")
	defer s.End(false)

	// If there's only one project defined in the devfile, sync to `/projects/project-name`, otherwise sync to /projects
	syncFolder, err := getSyncFolder(a.Devfile.Data.GetProjects())
	if err != nil {
		return errors.Wrapf(err, "unable to sync the files to the component")
	}

	if syncFolder != kclient.OdoSourceVolumeMount {
		// Need to make sure the folder already exists on the component or else sync will fail
		glog.V(4).Infof("Creating %s on the remote container if it doesn't already exist", syncFolder)
		cmdArr := getCmdToCreateSyncFolder(syncFolder)

		err = exec.ExecuteCommand(&a.Client, podName, containerName, cmdArr, false)
		if err != nil {
			return err
		}
	}
	// If there were any files deleted locally, delete them remotely too.
	if len(delFiles) > 0 {
		cmdArr := getCmdToDeleteFiles(delFiles, syncFolder)

		err = exec.ExecuteCommand(&a.Client, podName, containerName, cmdArr, false)
		if err != nil {
			return err
		}
	}

	if !isForcePush {
		if len(files) == 0 && len(delFiles) == 0 {
			// nothing to push
			s.End(true)
			return nil
		}
	}

	if isForcePush || len(files) > 0 {
		glog.V(4).Infof("Copying files %s to pod", strings.Join(files, " "))
		err = sync.CopyFile(&a.Client, path, podName, containerName, syncFolder, files, globExps)
		if err != nil {
			s.End(false)
			return errors.Wrap(err, "unable push files to pod")
		}
	}
	s.End(true)

	return nil
}

func (a Adapter) waitAndGetComponentPod(hideSpinner bool) (*corev1.Pod, error) {
	podSelector := fmt.Sprintf("component=%s", a.ComponentName)
	watchOptions := metav1.ListOptions{
		LabelSelector: podSelector,
	}
	// Wait for Pod to be in running state otherwise we can't sync data to it.
	pod, err := a.Client.WaitAndGetPod(watchOptions, corev1.PodRunning, "Waiting for component to start", hideSpinner)
	if err != nil {
		return nil, errors.Wrapf(err, "error while waiting for pod %s", podSelector)
	}
	return pod, nil
}

// Executes Devfile Commands
func (a Adapter) execDevfile(pushDevfileCommands []versionsCommon.DevfileCommand, componentExists, show bool, podName string, containers []corev1.Container, runInit bool) (err error) {
	var s *log.Status

	if len(pushDevfileCommands) == 0 {
		return errors.New(fmt.Sprint("error executing devfile commands - there should be at least 1 command."))
	}

	type CommandNames struct {
		defaultName string
		adapterName string
	}

	commandOrder := []CommandNames{}

	if runInit {
		commandOrder = append(commandOrder, CommandNames{defaultName: string(common.DefaultDevfileInitCommand), adapterName: a.devfileInitCmd})
	}
	commandOrder = append(
		commandOrder,
		CommandNames{defaultName: string(common.DefaultDevfileBuildCommand), adapterName: a.devfileBuildCmd},
		CommandNames{defaultName: string(common.DefaultDevfileRunCommand), adapterName: a.devfileRunCmd},
	)

	for i, currentCommand := range commandOrder {
		for _, command := range pushDevfileCommands {
			if command.Name == currentCommand.defaultName || command.Name == currentCommand.adapterName {
				if i < len(commandOrder)-1 {
					// Any exec command such as "Init" and "Build"
					err := a.executeDevfileCommand(command, show, podName)
					if err != nil {
						return err
					}
				} else {
					// Last command is "Run"
					glog.V(3).Infof("Executing devfile command %v", command.Name)

					for _, action := range command.Actions {

						// Check if the devfile run component containers have supervisord as the entrypoint.
						// Start the supervisord if the odo component does not exist
						if !componentExists {
							err = a.InitRunContainerSupervisord(*action.Component, podName, containers)
							if err != nil {
								return
							}
						}

						// Exec the supervisord ctl stop and start for the devrun program
						type devRunExecutable struct {
							command []string
						}
						devRunExecs := []devRunExecutable{
							{
								command: []string{common.SupervisordBinaryPath, "ctl", "stop", "all"},
							},
							{
								command: []string{common.SupervisordBinaryPath, "ctl", "start", string(common.DefaultDevfileRunCommand)},
							},
						}

						s = log.Spinner("Executing " + command.Name + " command " + fmt.Sprintf("%q", *action.Command))
						defer s.End(false)

						for _, devRunExec := range devRunExecs {

							err = exec.ExecuteCommand(&a.Client, podName, *action.Component, devRunExec.command, show)
							if err != nil {
								return
							}
						}
						s.End(true)
					}
				}
			}
		}
	}

	return
}

func (a Adapter) executeDevfileCommand(command versionsCommon.DevfileCommand, show bool, podName string) error {
	var s *log.Status
	glog.V(3).Infof("Executing devfile command %v", command.Name)

	for _, action := range command.Actions {
		// Change to the workdir and execute the command
		var cmdArr []string
		if action.Workdir != nil {
			cmdArr = []string{"/bin/sh", "-c", "cd " + *action.Workdir + " && " + *action.Command}
		} else {
			cmdArr = []string{"/bin/sh", "-c", *action.Command}
		}

		if show {
			s = log.SpinnerNoSpin("Executing " + command.Name + " command " + fmt.Sprintf("%q", *action.Command))
		} else {
			s = log.Spinner("Executing " + command.Name + " command " + fmt.Sprintf("%q", *action.Command))
		}

		defer s.End(false)

		err := exec.ExecuteCommand(&a.Client, podName, *action.Component, cmdArr, show)
		if err != nil {
			s.End(false)
			return err
		}
		s.End(true)
	}

	return nil
}

// InitRunContainerSupervisord initializes the supervisord in the container if
// the container has entrypoint that is not supervisord
func (a Adapter) InitRunContainerSupervisord(containerName, podName string, containers []corev1.Container) (err error) {
	for _, container := range containers {
		if container.Name == containerName && !reflect.DeepEqual(container.Command, []string{common.SupervisordBinaryPath}) {
			command := []string{common.SupervisordBinaryPath, "-c", common.SupervisordConfFile, "-d"}
			err = exec.ExecuteCommand(&a.Client, podName, containerName, command, true)
		}
	}

	return
}

// getFirstContainerWithSourceVolume returns the first container that set mountSources: true
// Because the source volume is shared across all components that need it, we only need to sync once,
// so we only need to find one container. If no container was found, that means there's no
// container to sync to, so return an error
func getFirstContainerWithSourceVolume(containers []corev1.Container) (string, error) {
	for _, c := range containers {
		for _, vol := range c.VolumeMounts {
			if vol.Name == kclient.OdoSourceVolume {
				return c.Name, nil
			}
		}
	}

	return "", fmt.Errorf("In order to sync files, odo requires at least one component in a devfile to set 'mountSources: true'")
}

// getSyncFolder returns the folder that we need to sync the source files to
// If there's exactly one project defined in the devfile, and clonePath isn't set return `/projects/<projectName>`
// If there's exactly one project, and clonePath is set, return `/projects/<clonePath>`
// If the clonePath is an absolute path or contains '..', return an error
// Otherwise (zero projects or many), return `/projects`
func getSyncFolder(projects []versionsCommon.DevfileProject) (string, error) {
	if len(projects) == 1 {
		project := projects[0]
		// If the clonepath is set to a value, set it to be the sync folder
		// As some devfiles rely on the code being synced to the folder in the clonepath
		if project.ClonePath != nil {
			if strings.HasPrefix(*project.ClonePath, "/") {
				return "", fmt.Errorf("the clonePath in the devfile must be a relative path")
			}
			if strings.Contains(*project.ClonePath, "..") {
				return "", fmt.Errorf("the clonePath in the devfile cannot escape the projects root. Don't use .. to try and do that")
			}
			return filepath.ToSlash(filepath.Join(kclient.OdoSourceVolumeMount, *project.ClonePath)), nil
		}
		return filepath.ToSlash(filepath.Join(kclient.OdoSourceVolumeMount, projects[0].Name)), nil
	}
	return kclient.OdoSourceVolumeMount, nil

}

// getCmdToCreateSyncFolder returns the command used to create the remote sync folder on the running container
func getCmdToCreateSyncFolder(syncFolder string) []string {
	return []string{"mkdir", "-p", syncFolder}
}

// getCmdToDeleteFiles returns the command used to delete the remote files on the container that are marked for deletion
func getCmdToDeleteFiles(delFiles []string, syncFolder string) []string {
	rmPaths := util.GetRemoteFilesMarkedForDeletion(delFiles, syncFolder)
	glog.V(4).Infof("remote files marked for deletion are %+v", rmPaths)
	cmdArr := []string{"rm", "-rf"}
	return append(cmdArr, rmPaths...)
}

// Delete deletes the component
func (a Adapter) Delete(labels map[string]string) error {
	if !utils.ComponentExists(a.Client, a.ComponentName) {
		return errors.Errorf("the component %s doesn't exist on the cluster", a.ComponentName)
	}

	return a.Client.DeleteDeployment(labels)
}
