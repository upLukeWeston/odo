package component

import (
	"testing"

	"github.com/docker/go-connections/nat"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/mount"
	adaptersCommon "github.com/openshift/odo/pkg/devfile/adapters/common"
	devfileParser "github.com/openshift/odo/pkg/devfile/parser"
	versionsCommon "github.com/openshift/odo/pkg/devfile/parser/data/common"
	envinfo "github.com/openshift/odo/pkg/envinfo"
	"github.com/openshift/odo/pkg/lclient"
	"github.com/openshift/odo/pkg/testingutil"
)

func TestCreateComponent(t *testing.T) {

	testComponentName := "test"
	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name       string
		components []versionsCommon.DevfileComponent
		client     *lclient.Client
		wantErr    bool
	}{
		{
			name:       "Case 1: Invalid devfile",
			components: []versionsCommon.DevfileComponent{},
			client:     fakeClient,
			wantErr:    true,
		},
		{
			name:       "Case 2: Valid devfile",
			components: []versionsCommon.DevfileComponent{testingutil.GetFakeComponent("alias1")},
			client:     fakeClient,
			wantErr:    false,
		},
		{
			name:       "Case 3: Valid devfile, docker client error",
			components: []versionsCommon.DevfileComponent{testingutil.GetFakeComponent("alias1")},
			client:     fakeErrorClient,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					ExecCommands: testingutil.GetFakeExecRunCommands(),
					Components:   tt.components,
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			err := componentAdapter.createComponent()

			// Checks for unexpected error cases
			if !tt.wantErr == (err != nil) {
				t.Errorf("component adapter create unexpected error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}

func TestUpdateComponent(t *testing.T) {

	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name          string
		components    []versionsCommon.DevfileComponent
		componentName string
		client        *lclient.Client
		wantErr       bool
	}{
		{
			name:          "Case 1: Invalid devfile",
			components:    []versionsCommon.DevfileComponent{},
			componentName: "",
			client:        fakeClient,
			wantErr:       true,
		},
		{
			name:          "Case 2: Valid devfile",
			components:    []versionsCommon.DevfileComponent{testingutil.GetFakeComponent("alias1")},
			componentName: "test",
			client:        fakeClient,
			wantErr:       false,
		},
		{
			name:          "Case 3: Valid devfile, docker client error",
			components:    []versionsCommon.DevfileComponent{testingutil.GetFakeComponent("alias1")},
			componentName: "",
			client:        fakeErrorClient,
			wantErr:       true,
		},
		{
			name: "Case 3: Valid devfile, missing component",
			components: []versionsCommon.DevfileComponent{
				{
					Container: &versionsCommon.Container{
						Name: "fakecomponent",
					},
				},
			},
			componentName: "fakecomponent",
			client:        fakeClient,
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components:   tt.components,
					ExecCommands: testingutil.GetFakeExecRunCommands(),
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: tt.componentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			_, err := componentAdapter.updateComponent()

			// Checks for unexpected error cases
			if !tt.wantErr == (err != nil) {
				t.Errorf("component adapter update unexpected error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}

func TestPullAndStartContainer(t *testing.T) {

	testComponentName := "test"
	testVolumeName := "projects"

	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name          string
		componentType versionsCommon.DevfileComponentType
		client        *lclient.Client
		mounts        []mount.Mount
		wantErr       bool
	}{
		{
			name:          "Case 1: Successfully start container, no mount",
			componentType: versionsCommon.ContainerComponentType,
			client:        fakeClient,
			mounts:        []mount.Mount{},
			wantErr:       false,
		},
		{
			name:          "Case 2: Docker client error",
			componentType: versionsCommon.ContainerComponentType,
			client:        fakeErrorClient,
			mounts:        []mount.Mount{},
			wantErr:       true,
		},
		{
			name:          "Case 3: Successfully start container, one mount",
			componentType: versionsCommon.ContainerComponentType,
			client:        fakeClient,
			mounts: []mount.Mount{
				{
					Source: "test-vol",
					Target: "/path",
				},
			},
			wantErr: false,
		},
		{
			name:          "Case 4: Successfully start container, multiple mounts",
			componentType: versionsCommon.ContainerComponentType,
			client:        fakeClient,
			mounts: []mount.Mount{
				{
					Source: "test-vol",
					Target: "/path",
				},
				{
					Source: "test-vol-two",
					Target: "/path-two",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components: []versionsCommon.DevfileComponent{
						testingutil.GetFakeComponent("alias1"),
					},
					ExecCommands: testingutil.GetFakeExecRunCommands(),
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			err := componentAdapter.pullAndStartContainer(tt.mounts, testVolumeName, adapterCtx.Devfile.Data.GetAliasedComponents()[0])

			// Checks for unexpected error cases
			if !tt.wantErr == (err != nil) {
				t.Errorf("component adapter create unexpected error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}

func TestStartContainer(t *testing.T) {

	testComponentName := "test"
	testVolumeName := "projects"

	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name    string
		client  *lclient.Client
		mounts  []mount.Mount
		wantErr bool
	}{
		{
			name:    "Case 1: Successfully start container, no mount",
			client:  fakeClient,
			mounts:  []mount.Mount{},
			wantErr: false,
		},
		{
			name:    "Case 2: Docker client error",
			client:  fakeErrorClient,
			mounts:  []mount.Mount{},
			wantErr: true,
		},
		{
			name:   "Case 3: Successfully start container, one mount",
			client: fakeClient,
			mounts: []mount.Mount{
				{
					Source: "test-vol",
					Target: "/path",
				},
			},
			wantErr: false,
		},
		{
			name:   "Case 4: Successfully start container, multiple mount",
			client: fakeClient,
			mounts: []mount.Mount{
				{
					Source: "test-vol",
					Target: "/path",
				},
				{
					Source: "test-vol-two",
					Target: "/path-two",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components: []versionsCommon.DevfileComponent{
						testingutil.GetFakeComponent("alias1"),
					},
					ExecCommands: testingutil.GetFakeExecRunCommands(),
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			err := componentAdapter.startComponent(tt.mounts, testVolumeName, adapterCtx.Devfile.Data.GetAliasedComponents()[0])

			// Checks for unexpected error cases
			if !tt.wantErr == (err != nil) {
				t.Errorf("component adapter create unexpected error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

}

func TestGenerateAndGetHostConfig(t *testing.T) {
	fakeClient := lclient.FakeNew()
	testComponentName := "test"
	componentType := versionsCommon.ContainerComponentType

	endpointName := []string{"8080/tcp", "9090/tcp", "9080/tcp"}
	var endpointPort = []int32{8080, 9090, 9080}
	var expectPortNameMapping = map[nat.Port]string{
		nat.Port("8080/tcp"): "url1",
		nat.Port("9090/tcp"): "url2",
		nat.Port("9080/tcp"): "url3",
	}

	tests := []struct {
		name         string
		urlValue     []envinfo.EnvInfoURL
		expectResult nat.PortMap
		client       *lclient.Client
		endpoints    []versionsCommon.Endpoint
	}{
		{
			name:         "Case 1: no port mappings",
			urlValue:     []envinfo.EnvInfoURL{},
			expectResult: nil,
			client:       fakeClient,
			endpoints:    []versionsCommon.Endpoint{},
		},
		{
			name: "Case 2: only one port mapping",
			urlValue: []envinfo.EnvInfoURL{
				{Name: "url1", Port: 8080, ExposedPort: 65432},
			},
			expectResult: nat.PortMap{
				"8080/tcp": []nat.PortBinding{
					{
						HostIP:   LocalhostIP,
						HostPort: "65432",
					},
				},
			},
			client: fakeClient,
			endpoints: []versionsCommon.Endpoint{
				{
					Name:       endpointName[0],
					TargetPort: endpointPort[0],
				},
			},
		},
		{
			name: "Case 3: multiple port mappings",
			urlValue: []envinfo.EnvInfoURL{
				{Name: "url1", Port: 8080, ExposedPort: 65432},
				{Name: "url2", Port: 9090, ExposedPort: 54321},
				{Name: "url3", Port: 9080, ExposedPort: 45678},
			},
			expectResult: nat.PortMap{
				"8080/tcp": []nat.PortBinding{
					{
						HostIP:   LocalhostIP,
						HostPort: "65432",
					},
				},
				"9090/tcp": []nat.PortBinding{
					{
						HostIP:   LocalhostIP,
						HostPort: "54321",
					},
				},
				"9080/tcp": []nat.PortBinding{
					{
						HostIP:   LocalhostIP,
						HostPort: "45678",
					},
				},
			},
			client: fakeClient,
			endpoints: []versionsCommon.Endpoint{
				{
					Name:       endpointName[0],
					TargetPort: endpointPort[0],
				},
				{
					Name:       endpointName[1],
					TargetPort: endpointPort[1],
				},
				{
					Name:       endpointName[2],
					TargetPort: endpointPort[2],
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components: []versionsCommon.DevfileComponent{
						{
							Type: componentType,
						},
					},
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			esi, err := envinfo.NewEnvSpecificInfo("")
			if err != nil {
				t.Error(err)
			}
			for _, url := range tt.urlValue {
				err = esi.SetConfiguration("URL", url)
				if err != nil {
					t.Error(err)
				}
			}
			componentAdapter := New(adapterCtx, *tt.client)
			hostConfig, portURLNameMapping, err := componentAdapter.generateAndGetHostConfig(tt.endpoints)
			if err != nil {
				t.Error(err)
			}

			if len(hostConfig.PortBindings) != len(tt.expectResult) {
				t.Errorf("host config PortBindings length mismatch: actual value %v, expected value %v", len(hostConfig.PortBindings), len(tt.expectResult))
			}
			if len(hostConfig.PortBindings) != 0 {
				for key, value := range hostConfig.PortBindings {
					if tt.expectResult[key][0].HostIP != value[0].HostIP || tt.expectResult[key][0].HostPort != value[0].HostPort {
						t.Errorf("host config PortBindings mismatch: actual value %v, expected value %v", hostConfig.PortBindings, tt.expectResult)
					}
				}
			}
			if len(portURLNameMapping) != 0 {
				for key, value := range portURLNameMapping {
					if expectPortNameMapping[key] != value {
						t.Errorf("port and urlName mapping mismatch for port %v: actual value %v, expected value %v", key, value, expectPortNameMapping[key])
					}
				}
			}
			err = esi.DeleteEnvInfoFile()
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestExecDevfile(t *testing.T) {

	testComponentName := "test"
	componentType := versionsCommon.ContainerComponentType
	command := "ls -la"
	workDir := "/tmp"
	component := "alias1"
	var actionType versionsCommon.DevfileCommandType = versionsCommon.ExecCommandType

	containers := []types.Container{
		{
			ID: "someid",
			Labels: map[string]string{
				"alias": "somealias",
			},
		},
		{
			ID: "someid2",
			Labels: map[string]string{
				"alias": "somealias2",
			},
		},
	}

	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name                string
		client              *lclient.Client
		pushDevfileCommands adaptersCommon.PushCommandsMap
		componentExists     bool
		wantErr             bool
	}{
		{
			name:   "Case 1: Successful devfile command exec of devbuild and devrun",
			client: fakeClient,
			pushDevfileCommands: adaptersCommon.PushCommandsMap{
				versionsCommon.RunCommandGroupType: versionsCommon.DevfileCommand{
					Exec: &versionsCommon.Exec{
						CommandLine: command,
						WorkingDir:  workDir,
						Component:   component,
						Group: &versionsCommon.Group{
							Kind: versionsCommon.RunCommandGroupType,
						},
					},
					Type: actionType,
				},
				versionsCommon.BuildCommandGroupType: versionsCommon.DevfileCommand{
					Exec: &versionsCommon.Exec{
						CommandLine: command,
						WorkingDir:  workDir,
						Component:   component,
						Group: &versionsCommon.Group{
							Kind: versionsCommon.BuildCommandGroupType,
						},
					},
					Type: actionType,
				},
			},
			componentExists: false,
			wantErr:         false,
		},
		{
			name:   "Case 2: Successful devfile command exec of devrun",
			client: fakeClient,
			pushDevfileCommands: adaptersCommon.PushCommandsMap{
				versionsCommon.RunCommandGroupType: versionsCommon.DevfileCommand{
					Exec: &versionsCommon.Exec{
						CommandLine: command,
						WorkingDir:  workDir,
						Component:   component,
						Group: &versionsCommon.Group{
							Kind: versionsCommon.RunCommandGroupType,
						},
					},
					Type: actionType,
				},
			},
			componentExists: true,
			wantErr:         false,
		},
		{
			name:                "Case 3: No devfile push commands should result in an err",
			client:              fakeClient,
			pushDevfileCommands: adaptersCommon.PushCommandsMap{},
			componentExists:     false,
			wantErr:             true,
		},
		{
			name:   "Case 4: Unsuccessful devfile command exec of devrun",
			client: fakeErrorClient,
			pushDevfileCommands: adaptersCommon.PushCommandsMap{
				versionsCommon.RunCommandGroupType: versionsCommon.DevfileCommand{
					Exec: &versionsCommon.Exec{
						CommandLine: command,
						WorkingDir:  workDir,
						Component:   component,
						Group: &versionsCommon.Group{
							Kind: versionsCommon.RunCommandGroupType,
						},
					},
					Type: actionType,
				},
			},
			componentExists: true,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components: []versionsCommon.DevfileComponent{
						{
							Type: componentType,
						},
					},
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			err := componentAdapter.execDevfile(tt.pushDevfileCommands, tt.componentExists, false, containers)
			if !tt.wantErr && err != nil {
				t.Errorf("TestExecDevfile error: unexpected error during executing devfile commands: %v", err)
			}
		})
	}
}

func TestInitRunContainerSupervisord(t *testing.T) {

	testComponentName := "test"
	componentType := versionsCommon.ContainerComponentType

	containers := []types.Container{
		{
			ID: "someid",
			Labels: map[string]string{
				"alias": "somealias",
			},
		},
		{
			ID: "someid2",
			Labels: map[string]string{
				"alias": "somealias2",
			},
		},
	}

	fakeClient := lclient.FakeNew()
	fakeErrorClient := lclient.FakeErrorNew()

	tests := []struct {
		name      string
		client    *lclient.Client
		component string
		wantErr   bool
	}{
		{
			name:      "Case 1: Successful initialization of supervisord",
			client:    fakeClient,
			component: "somealias",
			wantErr:   false,
		},
		{
			name:      "Case 2: Unsuccessful initialization of supervisord",
			client:    fakeErrorClient,
			component: "somealias",
			wantErr:   true,
		},
		{
			name:      "Case 3: Unsuccessful initialization of supervisord with wrong component",
			client:    fakeErrorClient,
			component: "somealias123",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			devObj := devfileParser.DevfileObj{
				Data: testingutil.TestDevfileData{
					Components: []versionsCommon.DevfileComponent{
						{
							Type: componentType,
						},
					},
				},
			}

			adapterCtx := adaptersCommon.AdapterContext{
				ComponentName: testComponentName,
				Devfile:       devObj,
			}

			componentAdapter := New(adapterCtx, *tt.client)
			err := componentAdapter.InitRunContainerSupervisord(tt.component, containers)
			if !tt.wantErr && err != nil {
				t.Errorf("TestInitRunContainerSupervisord error: unexpected error during init supervisord: %v", err)
			}
		})
	}
}
