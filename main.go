package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/a1ex-var1amov/flacon/version"
)

type ReconData struct {
	IsContainer         bool              `json:"is_container" yaml:"is_container"`
	Privileged          bool              `json:"privileged" yaml:"privileged"`
	Secrets             []string          `json:"secrets" yaml:"secrets"`
	SecretsFound        []string          `json:"secrets_found" yaml:"secrets_found"`
	SecretsInCluster    []string          `json:"k8s_secrets" yaml:"k8s_secrets"`
	ConfigMapsInCluster []string          `json:"k8s_configmaps" yaml:"k8s_configmaps"`
	CanCreatePod        bool              `json:"can_create_pod" yaml:"can_create_pod"`
	Misconfigs          []string          `json:"misconfigs" yaml:"misconfigs"`
	EscapePaths         []string          `json:"escape_paths" yaml:"escape_paths"`
	WritablePaths       []string          `json:"writable_paths" yaml:"writable_paths"`
	PlatformInfo        map[string]string `json:"platform_info" yaml:"platform_info"`
	BaseImage           string            `json:"base_image" yaml:"base_image"`
	EBPF                bool              `json:"ebpf_supported" yaml:"ebpf_supported"`
	CloneSyscall        bool              `json:"clone_syscall_allowed" yaml:"clone_syscall_allowed"`
}

func main() {
	// Check for version command
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Println(version.FullString())
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	format := "yaml" // change to "json" if needed
	var recon ReconData

	recon.IsContainer = isContainer()
	recon.PlatformInfo = detectPlatform()
	recon.BaseImage = detectBaseImage()
	recon.Privileged = checkPrivileged()
	recon.Secrets = checkSecrets()
	recon.SecretsFound = scanSecrets("/")
	recon.Misconfigs = checkMisconfigs()
	recon.EscapePaths = checkEscapePaths()
	recon.WritablePaths = checkWritablePaths([]string{"/", "/etc", "/var", "/host", "/mnt", "/app", "/data"})
	recon.EBPF = checkEBPFSupport()
	recon.CloneSyscall = checkCloneSyscall()

	recon.SecretsInCluster, recon.ConfigMapsInCluster = listK8sSecretsAndConfigMaps()
	recon.CanCreatePod = checkPodCreationRights()

	outputRecon(recon, format)
}

func printUsage() {
	fmt.Printf(`%s

Usage: flacon [command]

Commands:
  version, -v, --version    Show version information
  help, -h, --help         Show this help message
  (no args)                Run Kubernetes reconnaissance

Examples:
  flacon                   Run reconnaissance and output YAML
  flacon version           Show version information
  flacon --help            Show help message

`, version.String())
}

// --- Helper Functions Below ---

func isContainer() bool {
	if cgroup, err := ioutil.ReadFile("/proc/1/cgroup"); err == nil && strings.Contains(string(cgroup), "docker") {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

func detectPlatform() map[string]string {
	info := make(map[string]string)
	if content, err := ioutil.ReadFile("/proc/version"); err == nil {
		info["kernel_version"] = strings.TrimSpace(string(content))
	}
	if content, err := ioutil.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info["os"] = strings.Trim(line[len("PRETTY_NAME="):], "\"")
			}
		}
	}

	// Use runtime.GOARCH instead of unix.Uname for better cross-compilation support
	info["architecture"] = runtime.GOARCH

	return info
}

func detectBaseImage() string {
	paths := []string{"/etc/os-release", "/etc/alpine-release", "/etc/issue", "/etc/redhat-release"}
	for _, path := range paths {
		content, err := ioutil.ReadFile(path)
		if err == nil && len(content) > 0 {
			return fmt.Sprintf("Info from %s: %s", path, strings.TrimSpace(string(content)))
		}
	}
	if _, err := exec.LookPath("apk"); err == nil {
		return "Alpine (apk detected)"
	}
	if _, err := exec.LookPath("apt"); err == nil {
		return "Debian/Ubuntu (apt detected)"
	}
	if _, err := exec.LookPath("yum"); err == nil {
		return "RHEL/CentOS (yum detected)"
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		return "Fedora/RHEL (dnf detected)"
	}
	return "Unknown base image"
}

func checkPrivileged() bool {
	if _, err := os.Stat("/dev/kmsg"); err == nil {
		return true
	}
	return false
}

func checkSecrets() []string {
	paths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount",
		"/var/run/secrets/",
		"/etc/secrets/",
	}
	found := []string{}
	for _, p := range paths {
		files, err := ioutil.ReadDir(p)
		if err == nil {
			for _, f := range files {
				found = append(found, filepath.Join(p, f.Name()))
			}
		}
	}
	return found
}

func scanSecrets(root string) []string {
	var found []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 5*1024*1024 {
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		data := string(content)
		if strings.Contains(data, "Bearer ") || strings.Contains(data, "eyJ") || strings.Contains(data, "AKIA") || strings.Contains(data, "-----BEGIN") || strings.Contains(data, "access_token") || strings.Contains(data, "secret") {
			found = append(found, path)
		}
		return nil
	})
	return found
}

func checkMisconfigs() []string {
	misconfigs := []string{}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		misconfigs = append(misconfigs, "Docker socket mounted")
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		misconfigs = append(misconfigs, "Kubernetes env variable set")
	}
	return misconfigs
}

func checkEscapePaths() []string {
	escapes := []string{}
	if _, err := os.Stat("/proc/kcore"); err == nil {
		escapes = append(escapes, "/proc/kcore present")
	}
	return escapes
}

func checkWritablePaths(paths []string) []string {
	writable := []string{}
	for _, path := range paths {
		testFile := filepath.Join(path, ".write_test")
		err := ioutil.WriteFile(testFile, []byte("test"), 0644)
		if err == nil {
			writable = append(writable, path)
			os.Remove(testFile)
		}
	}
	return writable
}

func checkEBPFSupport() bool {
	_, err := os.Open("/sys/fs/bpf")
	return err == nil
}

func checkCloneSyscall() bool {
	// There is no unix.Fork in Go; as a placeholder, return false.
	return false
}

func outputRecon(data ReconData, format string) {
	switch format {
	case "json":
		out, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(out))
	case "yaml":
		out, _ := yaml.Marshal(&data)
		fmt.Println(string(out))
	default:
		fmt.Println("Unsupported format")
	}
}

func listK8sSecretsAndConfigMaps() ([]string, []string) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	secretsList, err := clientset.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, nil
	}
	configMapsList, err := clientset.CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, nil
	}

	secrets := []string{}
	for _, s := range secretsList.Items {
		secrets = append(secrets, s.Name)
	}

	configmaps := []string{}
	for _, c := range configMapsList.Items {
		configmaps = append(configmaps, c.Name)
	}

	return secrets, configmaps
}

func checkPodCreationRights() bool {
	config, err := rest.InClusterConfig()
	if err != nil {
		return false
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}
	// Try to create a dummy pod (dry-run)
	dummyPod := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "recon-dummy",
			Namespace: "default",
		},
	}
	client := clientset.CoreV1().RESTClient()
	result := client.Post().
		AbsPath("/api/v1/namespaces/default/pods").
		Param("dryRun", "All").
		Body(dummyPod).
		Do(context.TODO())
	return result.Error() == nil
}
