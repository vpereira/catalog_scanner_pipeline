package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	BaseContainerGun = "registry.opensuse.org/home/vpereirabr/dockerimages/containers/vpereirabr/dagger_runner:latest"
)

type CatalogScannerPipeline struct {
	BaseDir   string
	ImageName string
	BaseURL   string
}

func (m *CatalogScannerPipeline) ScanPipeline(ctx context.Context, imageGun string, baseDir string, baseUrl string) (string, error) {
	m.BaseDir = baseDir
	m.ImageName = imageGun
	m.BaseURL = baseUrl

	container := m.Skopeo(ctx, imageGun, baseDir)
	container = m.Trivy(ctx, container)
	stdout, err := m.PushTrivyResults(ctx, container)
	return stdout, err
}

// Skopeo copies an image to a tarball
func (m *CatalogScannerPipeline) Skopeo(ctx context.Context, imageGun string, baseDir string) *Container {
	tarFilename := m.calculateTarFilename()
	cmdArgs := GenerateSkopeoCmdArgs(imageGun, tarFilename)

	skopeoCmd := []string{"skopeo"}

	skopeoCmd = append(skopeoCmd, cmdArgs...)

	container := dag.Container().From(BaseContainerGun)

	return container.WithExec(skopeoCmd)
}

// Trivy scans the tarball for vulnerabilities
func (m *CatalogScannerPipeline) Trivy(ctx context.Context, container *Container) *Container {
	resultFilename := m.calculateJSONFilename()
	cmdArgs := generateTrivyCmdArgs(resultFilename, m.calculateTarFilename())
	trivyCmd := []string{"trivy"}

	trivyCmd = append(trivyCmd, cmdArgs...)

	return container.WithExec(trivyCmd)
}

func (m *CatalogScannerPipeline) PushTrivyResults(ctx context.Context, container *Container) (string, error) {
	cmdArgs := GenerateCURLCmdArgs(m.BaseURL, m.ImageName, m.calculateJSONFilename())
	curlCmd := []string{"curl"}
	curlCmd = append(curlCmd, cmdArgs...)
	stdout, err := container.WithExec(curlCmd).Stdout(ctx)

	if err != nil {
		return "", err
	}
	return stdout, nil
}

// calculateTarFilename generates the tar file name based on the base directory and image gun
func (m *CatalogScannerPipeline) calculateTarFilename() string {
	safeImageName := strings.ReplaceAll(m.ImageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	return filepath.Join(m.BaseDir, safeImageName+".tar")
}

// calculateTarFilename generates the tar file name based on the base directory and image gun
func (m *CatalogScannerPipeline) calculateJSONFilename() string {
	safeImageName := strings.ReplaceAll(m.ImageName, "/", "_")
	safeImageName = strings.ReplaceAll(safeImageName, ":", "_")
	return filepath.Join(m.BaseDir, safeImageName+".json")
}

func GenerateCURLCmdArgs(url string, imageName, jsonPath string) []string {
	urlWithParams := fmt.Sprintf("%s?image=%s", url, imageName)
	cmdArgs := []string{"-X", "POST", "-H", "Content-Type: application/json", "-d"}
	cmdArgs = append(cmdArgs, fmt.Sprintf("@%s", jsonPath), urlWithParams)
	return cmdArgs
}

// GenerateSkopeoCmdArgs generates the command line arguments for the skopeo command based on environment variables and input parameters.
func GenerateSkopeoCmdArgs(imageName, targetFilename string) []string {
	cmdArgs := []string{"copy", "--remove-signatures"}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")

	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--src-username", registryUsername, "--src-password", registryPassword)
	}

	// Add the rest of the command
	cmdArgs = append(cmdArgs, fmt.Sprintf("docker://%s", imageName), fmt.Sprintf("docker-archive://%s", targetFilename))

	return cmdArgs
}

// GenerateTrivyCmdArgs generates the command line arguments for the trivy command based on environment variables and input parameters.
func generateTrivyCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// Check if SLOW_RUN environment variable is set to "1" and add "--slow" parameter
	slowRun := os.Getenv("SLOW_RUN")
	if slowRun == "1" {
		cmdArgs = append(cmdArgs, "--slow")
	}

	cmdArgs = append(cmdArgs, "--format", "json", "--output", resultFileName, "--input", target)

	return cmdArgs
}
