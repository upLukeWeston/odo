package kclient

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktesting "k8s.io/client-go/testing"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/odo/pkg/devfile/adapters/common"
	"github.com/openshift/odo/pkg/util"
)

func TestCreatePVC(t *testing.T) {

	tests := []struct {
		name      string
		pvcName   string
		size      string
		namespace string
		labels    map[string]string
		wantErr   bool
	}{
		{
			name:      "Case: Valid pvc name",
			pvcName:   "mypvc",
			size:      "1Gi",
			namespace: "default",
			labels: map[string]string{
				"testpvc": "testpvc",
			},
			wantErr: false,
		},
		{
			name:      "Case: Invalid pvc name",
			pvcName:   "",
			size:      "1Gi",
			namespace: "default",
			labels: map[string]string{
				"testpvc": "testpvc",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// initialising the fakeclient
			fkclient, fkclientset := FakeNew()
			fkclient.Namespace = tt.namespace

			quantity, err := resource.ParseQuantity(tt.size)
			if err != nil {
				t.Errorf("resource.ParseQuantity unexpected error %v", err)
			}
			pvcSpec := GeneratePVCSpec(quantity)

			objectMeta := CreateObjectMeta(tt.pvcName, tt.namespace, tt.labels, nil)

			fkclientset.Kubernetes.PrependReactor("create", "persistentvolumeclaims", func(action ktesting.Action) (bool, runtime.Object, error) {
				if tt.pvcName == "" {
					return true, nil, errors.Errorf("pvc name is empty")
				}
				pvc := corev1.PersistentVolumeClaim{
					TypeMeta: metav1.TypeMeta{
						Kind:       PersistentVolumeClaimKind,
						APIVersion: PersistentVolumeClaimAPIVersion,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: tt.pvcName,
					},
				}
				return true, &pvc, nil
			})

			createdPVC, err := fkclient.CreatePVC(objectMeta, *pvcSpec)

			// Checks for unexpected error cases
			if !tt.wantErr == (err != nil) {
				t.Errorf("fkclient.CreatePVC unexpected error %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				if len(fkclientset.Kubernetes.Actions()) != 1 {
					t.Errorf("expected 1 action in StartPVC got: %v", fkclientset.Kubernetes.Actions())
				} else {
					if createdPVC.Name != tt.pvcName {
						t.Errorf("deployment name does not match the expected name, expected: %s, got %s", tt.pvcName, createdPVC.Name)
					}
				}
			}
		})
	}
}

func TestAddPVCToPodTemplateSpec(t *testing.T) {

	container := &corev1.Container{
		Name:            "container1",
		Image:           "image1",
		ImagePullPolicy: corev1.PullAlways,

		Command: []string{"tail"},
		Args:    []string{"-f", "/dev/null"},
		Env:     []corev1.EnvVar{},
	}

	tests := []struct {
		podName        string
		namespace      string
		serviceAccount string
		pvc            string
		volumeName     string
		labels         map[string]string
	}{
		{
			podName:        "podSpecTest",
			namespace:      "default",
			serviceAccount: "default",
			pvc:            "mypvc",
			volumeName:     "myvolume",
			labels: map[string]string{
				"app":       "app",
				"component": "frontend",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.podName, func(t *testing.T) {

			objectMeta := CreateObjectMeta(tt.podName, tt.namespace, tt.labels, nil)

			podTemplateSpec := GeneratePodTemplateSpec(objectMeta, []corev1.Container{*container})

			AddPVCToPodTemplateSpec(podTemplateSpec, tt.volumeName, tt.pvc)

			pvcMatched := false
			for _, volume := range podTemplateSpec.Spec.Volumes {
				if volume.Name == tt.volumeName && volume.VolumeSource.PersistentVolumeClaim != nil && volume.VolumeSource.PersistentVolumeClaim.ClaimName == tt.pvc {
					pvcMatched = true
				}
			}

			if !pvcMatched {
				t.Errorf("Volume does not exist with Volume Name %s and PVC claim name %s", tt.volumeName, tt.pvc)
			}

		})
	}
}

func TestAddVolumeMountToPodTemplateSpec(t *testing.T) {

	tests := []struct {
		podName                string
		namespace              string
		serviceAccount         string
		pvc                    string
		volumeName             string
		containerMountPathsMap map[string][]string
		container              corev1.Container
		labels                 map[string]string
		wantErr                bool
	}{
		{
			podName:        "podSpecTest",
			namespace:      "default",
			serviceAccount: "default",
			pvc:            "mypvc",
			volumeName:     "myvolume",
			containerMountPathsMap: map[string][]string{
				"container1": {"/tmp/path1", "/tmp/path2"},
			},
			container: corev1.Container{
				Name:            "container1",
				Image:           "image1",
				ImagePullPolicy: corev1.PullAlways,

				Command: []string{"tail"},
				Args:    []string{"-f", "/dev/null"},
				Env:     []corev1.EnvVar{},
			},
			labels: map[string]string{
				"app":       "app",
				"component": "frontend",
			},
			wantErr: false,
		},
		{
			podName:        "podSpecTest",
			namespace:      "default",
			serviceAccount: "default",
			pvc:            "mypvc",
			volumeName:     "myvolume",
			containerMountPathsMap: map[string][]string{
				"container1": {"/tmp/path1", "/tmp/path2"},
			},
			container: corev1.Container{},
			labels: map[string]string{
				"app":       "app",
				"component": "frontend",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.podName, func(t *testing.T) {

			objectMeta := CreateObjectMeta(tt.podName, tt.namespace, tt.labels, nil)

			podTemplateSpec := GeneratePodTemplateSpec(objectMeta, []corev1.Container{tt.container})

			err := AddVolumeMountToPodTemplateSpec(podTemplateSpec, tt.volumeName, tt.containerMountPathsMap)
			if !tt.wantErr && err != nil {
				t.Errorf("TestAddVolumeMountToPodTemplateSpec.AddVolumeMountToPodTemplateSpec() unexpected error %v, wantErr %v", err, tt.wantErr)
			}

			mountPathCount := 0
			for _, podTempSpecContainer := range podTemplateSpec.Spec.Containers {
				if podTempSpecContainer.Name == tt.container.Name {
					for _, volumeMount := range podTempSpecContainer.VolumeMounts {
						if volumeMount.Name == tt.volumeName {
							for _, mountPath := range tt.containerMountPathsMap[tt.container.Name] {
								if volumeMount.MountPath == mountPath {
									mountPathCount++
								}
							}
						}
					}
				}
			}

			if mountPathCount != len(tt.containerMountPathsMap[tt.container.Name]) {
				t.Errorf("Volume Mounts for %s have not been properly mounted to the podTemplateSpec", tt.volumeName)
			}
		})
	}
}

func TestGetPVCsFromSelector(t *testing.T) {
	tests := []struct {
		name      string
		pvcName   string
		size      string
		namespace string
		labels    map[string]string
		wantErr   bool
	}{
		{
			name:      "Case: Valid pvc name",
			pvcName:   "mypvc",
			size:      "1Gi",
			namespace: "default",
			labels: map[string]string{
				"mylabel1": "testpvc1",
				"mylabel2": "testpvc2",
			},
			wantErr: false,
		},
		{
			name:      "Case: Wrong Label Selector",
			pvcName:   "mypvc",
			size:      "1Gi",
			namespace: "default",
			labels: map[string]string{
				"mylabel1": "testpvc1",
				"mylabel2": "testpvc2",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// initialising the fakeclient
			fkclient, fkclientset := FakeNew()
			fkclient.Namespace = tt.namespace

			selector := util.ConvertLabelsToSelector(tt.labels)

			listOfPVC := corev1.PersistentVolumeClaimList{
				Items: []corev1.PersistentVolumeClaim{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:   tt.pvcName,
							Labels: tt.labels,
						},
					},
				},
			}

			fkclientset.Kubernetes.PrependReactor("list", "persistentvolumeclaims", func(action ktesting.Action) (bool, runtime.Object, error) {
				if tt.name == "Case: Wrong Label Selector" {
					return true, nil, fmt.Errorf("TestGetPVCsFromSelector: Labels do not match with expected values, expected:%s, got:%s", selector, selector+",garbage=true")
				}
				return true, &listOfPVC, nil
			})

			PVCs, err := fkclient.GetPVCsFromSelector(selector)
			if !tt.wantErr && err != nil {
				t.Errorf("TestGetPVCsFromSelector: Error listing PVCs with selector: %v", err)
			}

			if len(PVCs) == 0 || len(PVCs) > 1 {
				if !tt.wantErr {
					t.Errorf("TestGetPVCsFromSelector: Incorrect amount of PVC found with selector %s", selector)
				}
			} else {
				for _, PVC := range PVCs {
					if PVC.Name != tt.pvcName {
						t.Errorf("TestGetPVCsFromSelector: PVC found with incorrect name, expected: %s actual: %s", tt.pvcName, PVC.Name)
					}
					if !reflect.DeepEqual(PVC.Labels, tt.labels) {
						t.Errorf("TestGetPVCsFromSelector: Labels do not match with expected labels, expected: %s, got %s", tt.labels, PVC.Labels)
					}
				}
			}
		})
	}
}

func TestAddPVCAndVolumeMount(t *testing.T) {

	volNames := [...]string{"volume1", "volume2", "volume3"}
	volContainerPath := [...]string{"/home/user/path1", "/home/user/path2", "/home/user/path3"}

	tests := []struct {
		name                    string
		podName                 string
		namespace               string
		labels                  map[string]string
		containers              []corev1.Container
		volumeNameToPVCName     map[string]string
		componentAliasToVolumes map[string][]common.DevfileVolume
		wantErr                 bool
	}{
		{
			name:      "Case: Valid case",
			podName:   "podSpecTest",
			namespace: "default",
			labels: map[string]string{
				"app":       "app",
				"component": "frontend",
			},
			containers: []corev1.Container{
				{
					Name:            "container1",
					Image:           "image1",
					ImagePullPolicy: corev1.PullAlways,

					Command: []string{"tail"},
					Args:    []string{"-f", "/dev/null"},
					Env:     []corev1.EnvVar{},
				},
				{
					Name:            "container2",
					Image:           "image2",
					ImagePullPolicy: corev1.PullAlways,

					Command: []string{"tail"},
					Args:    []string{"-f", "/dev/null"},
					Env:     []corev1.EnvVar{},
				},
			},
			volumeNameToPVCName: map[string]string{
				"volume1": "volume1-pvc",
				"volume2": "volume2-pvc",
				"volume3": "volume3-pvc",
			},
			componentAliasToVolumes: map[string][]common.DevfileVolume{
				"container1": []common.DevfileVolume{
					{
						Name:          volNames[0],
						ContainerPath: volContainerPath[0],
					},
					{
						Name:          volNames[0],
						ContainerPath: volContainerPath[1],
					},
					{
						Name:          volNames[1],
						ContainerPath: volContainerPath[2],
					},
				},
				"container2": []common.DevfileVolume{
					{
						Name:          volNames[1],
						ContainerPath: volContainerPath[1],
					},
					{
						Name:          volNames[2],
						ContainerPath: volContainerPath[2],
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "Case: Error case",
			podName:   "podSpecTest",
			namespace: "default",
			labels: map[string]string{
				"app":       "app",
				"component": "frontend",
			},
			containers: []corev1.Container{},
			volumeNameToPVCName: map[string]string{
				"volume2": "volume2-pvc",
				"volume3": "volume3-pvc",
			},
			componentAliasToVolumes: map[string][]common.DevfileVolume{
				"container2": []common.DevfileVolume{
					{
						Name:          volNames[1],
						ContainerPath: volContainerPath[1],
					},
					{
						Name:          volNames[2],
						ContainerPath: volContainerPath[2],
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			objectMeta := CreateObjectMeta(tt.podName, tt.namespace, tt.labels, nil)

			podTemplateSpec := GeneratePodTemplateSpec(objectMeta, tt.containers)

			err := AddPVCAndVolumeMount(podTemplateSpec, tt.volumeNameToPVCName, tt.componentAliasToVolumes)
			if !tt.wantErr && err != nil {
				t.Errorf("TestAddPVCAndVolumeMount.AddPVCAndVolumeMount() unexpected error %v, wantErr %v", err, tt.wantErr)
			} else if tt.wantErr && err != nil {
				return
			}

			// The total number of expected volumes is equal to the number of volumes defined in the devfile plus two (emptyDir source and supervisord volumes)
			expectedNumVolumes := len(tt.volumeNameToPVCName) + 2

			// check the number of containers and volumes in the pod template spec
			if len(podTemplateSpec.Spec.Containers) != len(tt.containers) {
				t.Errorf("Incorrect number of Containers found in the pod template spec, expected: %v found: %v", len(tt.containers), len(podTemplateSpec.Spec.Containers))
				return
			}
			if len(podTemplateSpec.Spec.Volumes) != expectedNumVolumes {
				t.Errorf("TestAddPVCAndVolumeMount incorrect amount of pvc volumes in pod template spec expected %v, actual %v", expectedNumVolumes, len(podTemplateSpec.Spec.Volumes))
				return
			}

			// check the volume mounts of the pod template spec containers
			for _, container := range podTemplateSpec.Spec.Containers {
				for testcontainerAlias, testContainerVolumes := range tt.componentAliasToVolumes {
					if container.Name == testcontainerAlias {
						// check if container has the correct number of volume mounts
						if len(container.VolumeMounts) != len(testContainerVolumes) {
							t.Errorf("Incorrect number of Volume Mounts found in the pod template spec container %v, expected: %v found: %v", container.Name, len(testContainerVolumes), len(container.VolumeMounts))
						}

						// check if container has the specified volume
						volumeMatched := 0
						for _, volumeMount := range container.VolumeMounts {
							for _, testVolume := range testContainerVolumes {
								testVolumeName := testVolume.Name
								testVolumePath := testVolume.ContainerPath
								if strings.Contains(volumeMount.Name, testVolumeName) && volumeMount.MountPath == testVolumePath {
									volumeMatched++
								}
							}
						}
						if volumeMatched != len(testContainerVolumes) {
							t.Errorf("Failed to match Volume Mounts for pod template spec container %v, expected: %v found: %v", container.Name, len(testContainerVolumes), volumeMatched)
						}
					}
				}
			}
		})
	}
}
