package utils

import (
	"fmt"
	"strconv"

	"github.com/docker/go-connections/nat"
	"k8s.io/klog"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"

	adaptersCommon "github.com/openshift/odo/pkg/devfile/adapters/common"
	"github.com/openshift/odo/pkg/devfile/adapters/docker/storage"
	"github.com/openshift/odo/pkg/devfile/parser/data/common"
	"github.com/openshift/odo/pkg/lclient"
	"github.com/openshift/odo/pkg/log"
	"github.com/openshift/odo/pkg/util"

	"github.com/pkg/errors"
)

const (
	supervisordVolume = "supervisord"
	projectsVolume    = "projects"
	volume            = "vol"
)

// ComponentExists checks if Docker containers labeled with the specified component name exists
func ComponentExists(client lclient.Client, name string) bool {
	containers, err := GetComponentContainers(client, name)
	if err != nil {
		// log the error since this function basically returns a bool
		log.Error(err)
		return false
	}
	return len(containers) != 0
}

// GetComponentContainers returns a list of the running component containers
func GetComponentContainers(client lclient.Client, componentName string) (containers []types.Container, err error) {
	containerList, err := client.GetContainerList()
	if err != nil {
		return nil, err
	}
	containers = client.GetContainersByComponent(componentName, containerList)

	return containers, nil
}

// GetContainerIDForAlias returns the container ID for the devfile alias from a list of containers
func GetContainerIDForAlias(containers []types.Container, alias string) string {
	containerID := ""
	for _, container := range containers {
		if container.Labels["alias"] == alias {
			containerID = container.ID
		}
	}
	return containerID
}

// ConvertEnvs converts environment variables from the devfile structure to an array of strings, as expected by Docker
func ConvertEnvs(vars []common.Env) []string {
	dockerVars := []string{}
	for _, env := range vars {
		envString := fmt.Sprintf("%s=%s", env.Name, env.Value)
		dockerVars = append(dockerVars, envString)
	}
	return dockerVars
}

// ConvertPorts converts endpoints from the devfile structure to PortSet, which is expected by Docker
func ConvertPorts(endpoints []common.Endpoint) nat.PortSet {
	portSet := nat.PortSet{}
	for _, endpoint := range endpoints {
		port := nat.Port(strconv.Itoa(int(endpoint.TargetPort)) + "/tcp")
		portSet[port] = struct{}{}
	}
	return portSet
}

// DoesContainerNeedUpdating returns true if a given container needs to be removed and recreated
// This function compares values in the container vs corresponding values in the devfile component.
// If any of the values between the two differ, a restart is required (and this function returns true)
// Unlike Kube, Docker doesn't provide a mechanism to update a container in place only when necesary
// so this function is necessary to prevent having to restart the container on every odo pushs
func DoesContainerNeedUpdating(component common.DevfileComponent, containerConfig *container.Config, hostConfig *container.HostConfig, devfileMounts []mount.Mount, containerMounts []types.MountPoint, portMap nat.PortMap) bool {
	// If the image was changed in the devfile, the container needs to be updated
	if component.Container.Image != containerConfig.Image {
		return true
	}

	// Update the container if the volumes were updated in the devfile
	for _, devfileMount := range devfileMounts {
		if !containerHasMount(devfileMount, containerMounts) {
			return true
		}
	}

	// Update the container if the env vars were updated in the devfile
	// Need to convert the devfile envvars to the format expected by Docker
	devfileEnvVars := ConvertEnvs(component.Container.Env)
	for _, envVar := range devfileEnvVars {
		if !containerHasEnvVar(envVar, containerConfig.Env) {
			return true
		}
	}

	devfilePorts := ConvertPorts(component.Container.Endpoints)
	for port := range devfilePorts {
		if !containerHasPort(port, containerConfig.ExposedPorts) {
			return true
		}
	}

	for localInternalPort, localPortbinding := range portMap {
		if hostConfig.PortBindings[localInternalPort] == nil || hostConfig.PortBindings[localInternalPort][0].HostPort != localPortbinding[0].HostPort {
			// if there is no exposed port assigned to the internal port for the container, or if the exposed port has changed
			return true
		}
	}

	for containerInternalPort := range hostConfig.PortBindings {
		if portMap[containerInternalPort] == nil {
			// if the url is locally deleted
			return true
		}
	}

	return false
}

// AddVolumeToContainer adds the volume name and mount to the container host config
func AddVolumeToContainer(volumeName, volumeMount string, hostConfig *container.HostConfig) *container.HostConfig {
	mount := mount.Mount{
		Type:   mount.TypeVolume,
		Source: volumeName,
		Target: volumeMount,
	}
	hostConfig.Mounts = append(hostConfig.Mounts, mount)

	return hostConfig
}

// GetProjectVolumeLabels returns the label selectors used to retrieve the project/source volume for a given component
func GetProjectVolumeLabels(componentName string) map[string]string {
	volumeLabels := map[string]string{
		"component": componentName,
		"type":      projectsVolume,
	}
	return volumeLabels
}

// GetContainerLabels returns the label selectors used to retrieve/create the component container
func GetContainerLabels(componentName, alias string) map[string]string {
	containerLabels := map[string]string{
		"component": componentName,
		"alias":     alias,
	}
	return containerLabels
}

// GetSupervisordVolumeLabels returns the label selectors used to retrieve the supervisord volume
func GetSupervisordVolumeLabels() map[string]string {
	image := adaptersCommon.GetBootstrapperImage()
	_, _, _, imageTag := util.ParseComponentImageName(image)

	supervisordLabels := map[string]string{
		"name":    adaptersCommon.SupervisordVolumeName,
		"type":    supervisordVolume,
		"version": imageTag,
	}
	return supervisordLabels
}

// containerHasEnvVar returns true if the specified env var (and value) exist in the list of container env vars
func containerHasEnvVar(envVar string, containerEnv []string) bool {
	for _, env := range containerEnv {
		if envVar == env {
			return true
		}
	}
	return false
}

// containerHasMount returns true if the specified volume is mounted in the given container
func containerHasMount(devfileMount mount.Mount, containerMounts []types.MountPoint) bool {
	for _, mount := range containerMounts {
		if devfileMount.Source == mount.Name && devfileMount.Target == mount.Destination {
			return true
		}
	}
	return false
}

func containerHasPort(devfilePort nat.Port, exposedPorts nat.PortSet) bool {
	for port := range exposedPorts {
		if devfilePort.Port() == port.Port() {
			return true
		}
	}
	return false
}

// UpdateComponentWithSupervisord updates the devfile component's
// 1. command and args with supervisord, if absent
// 2. env with ODO_COMMAND_RUN and ODO_COMMAND_RUN_WORKING_DIR, if absent
func UpdateComponentWithSupervisord(comp *common.DevfileComponent, runCommand common.DevfileCommand, supervisordVolumeName string, hostConfig *container.HostConfig) {

	// Mount the supervisord volume for the run command container
	if runCommand.Exec.Component == comp.Container.Name {
		AddVolumeToContainer(supervisordVolumeName, adaptersCommon.SupervisordMountPath, hostConfig)

		if len(comp.Container.Command) == 0 && len(comp.Container.Args) == 0 {
			klog.V(4).Infof("Updating container %v entrypoint with supervisord", comp.Container.Name)
			comp.Container.Command = append(comp.Container.Command, adaptersCommon.SupervisordBinaryPath)
			comp.Container.Args = append(comp.Container.Args, "-c", adaptersCommon.SupervisordConfFile)
		}

		if !adaptersCommon.IsEnvPresent(comp.Container.Env, adaptersCommon.EnvOdoCommandRun) {
			envName := adaptersCommon.EnvOdoCommandRun
			envValue := runCommand.Exec.CommandLine
			comp.Container.Env = append(comp.Container.Env, common.Env{
				Name:  envName,
				Value: envValue,
			})
		}

		if !adaptersCommon.IsEnvPresent(comp.Container.Env, adaptersCommon.EnvOdoCommandRunWorkingDir) && runCommand.Exec.WorkingDir != "" {
			envName := adaptersCommon.EnvOdoCommandRunWorkingDir
			envValue := runCommand.Exec.WorkingDir
			comp.Container.Env = append(comp.Container.Env, common.Env{
				Name:  envName,
				Value: envValue,
			})
		}
	}
}

// CreateAndInitSupervisordVolume creates the supervisord volume and initializes
// it with supervisord bootstrap image - assembly files and supervisord binary
func CreateAndInitSupervisordVolume(client lclient.Client) (string, error) {
	log.Info("\nInitialization")
	s := log.Spinner("Initializing the component")
	defer s.End(false)

	supervisordVolumeName, err := storage.GenerateVolName(adaptersCommon.SupervisordVolumeName, volume)
	if err != nil {
		return "", errors.Wrapf(err, "unable to generate volume name for supervisord")
	}

	supervisordLabels := GetSupervisordVolumeLabels()
	_, err = client.CreateVolume(supervisordVolumeName, supervisordLabels)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to create supervisord volume for component")
	}

	err = StartBootstrapSupervisordInitContainer(client, supervisordVolumeName)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to start supervisord container for component")
	}
	s.End(true)

	return supervisordVolumeName, nil
}

// StartBootstrapSupervisordInitContainer pulls the supervisord bootstrap image, mounts the supervisord
// volume, starts the bootstrap container and initializes the supervisord volume via its entrypoint
func StartBootstrapSupervisordInitContainer(client lclient.Client, supervisordVolumeName string) error {
	supervisordLabels := GetSupervisordVolumeLabels()

	image := adaptersCommon.GetBootstrapperImage()
	command := []string{"/usr/bin/cp"}
	args := []string{
		"-r",
		adaptersCommon.OdoInitImageContents,
		adaptersCommon.SupervisordMountPath,
	}

	var s *log.Status
	if log.IsDebug() {
		s = log.Spinnerf("Pulling image %s", image)
		defer s.End(false)
	}

	err := client.PullImage(image)
	if err != nil {
		return errors.Wrapf(err, "unable to pull %s image", image)
	}
	if log.IsDebug() {
		s.End(true)
	}

	containerConfig := client.GenerateContainerConfig(image, command, args, nil, supervisordLabels, nil)
	hostConfig := container.HostConfig{}

	AddVolumeToContainer(supervisordVolumeName, adaptersCommon.SupervisordMountPath, &hostConfig)

	// Create the docker container
	if log.IsDebug() {
		s = log.Spinnerf("Starting container for %s", image)
		defer s.End(false)
	}
	err = client.StartContainer(&containerConfig, &hostConfig, nil)
	if err != nil {
		return err
	}
	if log.IsDebug() {
		s.End(true)
	}

	return nil
}
