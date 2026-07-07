// Package iacdetect derives a baseline set of architecture components from a
// directory's infrastructure-as-code, so a threat model can be bootstrapped from
// what the repo actually declares rather than typed by hand. It is deterministic
// and dependency-light: Terraform resources are matched by type, and Kubernetes
// / docker-compose manifests by kind and image. Every detected component maps to
// a threatlib tech so STRIDE can be enumerated over it.
//
// This is a heuristic baseline, not a full IaC parser. It favors recall (surface
// the obvious database, object store, API, auth service) over precision; a human
// edits the result. It never executes anything and reads at most a bounded slice
// of each file.
package iacdetect

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Supported formats: Terraform (.tf), CloudFormation/SAM (JSON + YAML),
// Kubernetes manifests, docker-compose, Bicep (.bicep), ARM templates (JSON),
// Pulumi (Pulumi.yaml programs plus TS/Python entrypoints beside a
// Pulumi.yaml), and Helm (values*.yaml image repositories, Chart.yaml
// dependencies, templated workload manifests).

// Component is one detected architecture node.
type Component struct {
	Name   string `json:"name"`
	Tech   string `json:"tech"`   // a threatlib tech id
	Source string `json:"source"` // the file it was detected in (repo-relative)
}

// maxFileBytes bounds how much of any one file is read.
const maxFileBytes = 512 * 1024

// maxCandidateFiles bounds how many matching files are scanned and
// maxWalkEntries how many directory entries are visited, so a pathological
// tree can't pin the request that triggered the scan. Recall on any sane repo
// is unaffected; a tree that trips these caps needs a human anyway.
const (
	maxCandidateFiles = 2000
	maxWalkEntries    = 200000
)

// tfResourceTech maps a Terraform resource type prefix to a threatlib tech. The
// longest matching prefix wins, so "aws_db_instance" beats a broader rule.
var tfResourceTech = []struct{ prefix, tech string }{
	// AWS data stores
	{"aws_db_instance", "database"},
	{"aws_rds_cluster", "database"},
	{"aws_dynamodb_table", "database"},
	{"aws_elasticache", "database"},
	{"aws_memorydb", "database"},
	{"aws_redshift", "database"},
	{"aws_docdb", "database"},
	{"aws_neptune", "database"},
	{"aws_opensearch", "database"},
	{"aws_elasticsearch_domain", "database"},
	// Azure data stores (both the legacy azurerm_sql_* and current azurerm_mssql_* names)
	{"azurerm_postgresql", "database"},
	{"azurerm_mysql", "database"},
	{"azurerm_mariadb", "database"},
	{"azurerm_sql", "database"},
	{"azurerm_mssql", "database"},
	{"azurerm_cosmosdb", "database"},
	{"azurerm_redis_cache", "database"},
	// GCP data stores
	{"google_sql_database_instance", "database"},
	{"google_bigquery", "database"},
	{"google_bigtable", "database"},
	{"google_spanner", "database"},
	{"google_firestore", "database"},
	{"google_redis_instance", "database"},
	// Object storage
	{"aws_s3_bucket", "object-store"},
	{"azurerm_storage_account", "object-store"},
	{"azurerm_storage_container", "object-store"},
	{"google_storage_bucket", "object-store"},
	// Compute / API surfaces
	{"aws_lb", "api-service"},
	{"aws_alb", "api-service"},
	{"aws_elb", "api-service"},
	{"aws_api_gateway", "api-service"},
	{"aws_apigatewayv2", "api-service"},
	{"aws_lambda_function", "api-service"},
	{"aws_ecs_service", "api-service"},
	{"aws_ecs_task_definition", "api-service"},
	{"aws_eks_", "api-service"},
	{"aws_apprunner", "api-service"},
	{"google_cloud_run", "api-service"},
	{"google_cloudfunctions", "api-service"},
	{"google_container_cluster", "api-service"},
	{"google_api_gateway", "api-service"},
	{"azurerm_kubernetes_cluster", "api-service"},
	{"azurerm_function_app", "api-service"},
	{"azurerm_linux_function_app", "api-service"},
	{"azurerm_windows_function_app", "api-service"},
	{"azurerm_api_management", "api-service"},
	{"azurerm_application_gateway", "api-service"},
	// Identity
	{"aws_cognito", "auth-service"},
	{"auth0_", "auth-service"},
	{"okta_", "auth-service"},
	{"keycloak_", "auth-service"},
	{"azuread_application", "auth-service"},
	{"google_identity_platform", "auth-service"},
	// Web frontends
	{"aws_cloudfront_distribution", "web-app"},
	{"aws_amplify_app", "web-app"},
	{"aws_elastic_beanstalk", "web-app"},
	{"azurerm_app_service", "web-app"},
	{"azurerm_linux_web_app", "web-app"},
	{"azurerm_windows_web_app", "web-app"},
	{"azurerm_cdn", "web-app"},
	{"google_app_engine", "web-app"},
}

// cfnTypeTech maps a CloudFormation resource Type token to a tech.
var cfnTypeTech = []struct{ contains, tech string }{
	{"AWS::RDS::", "database"},
	{"AWS::DynamoDB::", "database"},
	{"AWS::ElastiCache::", "database"},
	{"AWS::Redshift::", "database"},
	{"AWS::DocDB::", "database"},
	{"AWS::Neptune::", "database"},
	{"AWS::OpenSearchService::", "database"},
	{"AWS::Elasticsearch::", "database"},
	{"AWS::S3::Bucket", "object-store"},
	{"AWS::ElasticLoadBalancingV2::", "api-service"},
	{"AWS::ElasticLoadBalancing::", "api-service"},
	{"AWS::ApiGateway", "api-service"},
	{"AWS::Lambda::Function", "api-service"},
	{"AWS::ECS::Service", "api-service"},
	{"AWS::EKS::", "api-service"},
	{"AWS::AppRunner::", "api-service"},
	// SAM transforms (template.yaml is the default artifact name)
	{"AWS::Serverless::Function", "api-service"},
	{"AWS::Serverless::Api", "api-service"},
	{"AWS::Serverless::HttpApi", "api-service"},
	{"AWS::Cognito::", "auth-service"},
	{"AWS::CloudFront::", "web-app"},
	{"AWS::ElasticBeanstalk::", "web-app"},
}

// imageTech maps a substring of a container image to a tech (k8s / compose).
var imageTech = []struct{ contains, tech string }{
	{"postgres", "database"},
	{"mysql", "database"},
	{"mariadb", "database"},
	{"mongo", "database"},
	{"redis", "database"},
	{"cassandra", "database"},
	{"couchdb", "database"},
	{"elasticsearch", "database"},
	{"opensearch", "database"},
	{"memcached", "database"},
	{"minio", "object-store"},
	{"nginx", "web-app"},
	{"httpd", "web-app"},
	{"traefik", "web-app"},
	{"caddy", "web-app"},
	{"haproxy", "web-app"},
	{"keycloak", "auth-service"},
	{"dex", "auth-service"},
	{"vault", "auth-service"},
	{"authelia", "auth-service"},
	{"oauth2-proxy", "auth-service"},
}

// bicepArmTech maps an Azure resource-provider namespace (Bicep resource
// types and ARM template "type" values share it) to a tech.
var bicepArmTech = []struct{ contains, tech string }{
	{"Microsoft.Sql/", "database"},
	{"Microsoft.DBforPostgreSQL/", "database"},
	{"Microsoft.DBforMySQL/", "database"},
	{"Microsoft.DBforMariaDB/", "database"},
	{"Microsoft.DocumentDB/", "database"},
	{"Microsoft.Cache/", "database"},
	{"Microsoft.Storage/", "object-store"},
	{"Microsoft.ContainerService/", "api-service"},
	{"Microsoft.App/", "api-service"},
	{"Microsoft.ApiManagement/", "api-service"},
	{"Microsoft.Network/applicationGateways", "api-service"},
	{"Microsoft.Web/sites", "web-app"},
	{"Microsoft.Cdn/", "web-app"},
	{"Microsoft.AzureActiveDirectory", "auth-service"},
	{"Microsoft.AAD/", "auth-service"},
}

// pulumiTypeTech maps a Pulumi type token (aws:s3/bucket:Bucket in YAML
// programs) or a provider.module pair from a TS/Python program (aws.s3) to a
// tech. Keys are lowercase; matching is on the "provider:module" or
// "provider.module" prefix normalized to "provider.module".
var pulumiModuleTech = []struct{ prefix, tech string }{
	{"aws.s3", "object-store"},
	{"aws.rds", "database"},
	{"aws.dynamodb", "database"},
	{"aws.elasticache", "database"},
	{"aws.redshift", "database"},
	{"aws.docdb", "database"},
	{"aws.neptune", "database"},
	{"aws.opensearch", "database"},
	{"aws.lambda", "api-service"},
	{"aws.apigateway", "api-service"},
	{"aws.apigatewayv2", "api-service"},
	{"aws.ecs", "api-service"},
	{"aws.eks", "api-service"},
	{"aws.lb", "api-service"},
	{"aws.alb", "api-service"},
	{"aws.elb", "api-service"},
	{"aws.apprunner", "api-service"},
	{"aws.cognito", "auth-service"},
	{"aws.cloudfront", "web-app"},
	{"aws.amplify", "web-app"},
	{"gcp.sql", "database"},
	{"gcp.bigquery", "database"},
	{"gcp.spanner", "database"},
	{"gcp.bigtable", "database"},
	{"gcp.firestore", "database"},
	{"gcp.redis", "database"},
	{"gcp.storage", "object-store"},
	{"gcp.cloudrun", "api-service"},
	{"gcp.cloudrunv2", "api-service"},
	{"gcp.cloudfunctions", "api-service"},
	{"gcp.cloudfunctionsv2", "api-service"},
	{"gcp.container", "api-service"},
	{"gcp.apigateway", "api-service"},
	{"gcp.identityplatform", "auth-service"},
	{"gcp.appengine", "web-app"},
	{"azure.sql", "database"},
	{"azure.mssql", "database"},
	{"azure.postgresql", "database"},
	{"azure.mysql", "database"},
	{"azure.cosmosdb", "database"},
	{"azure.redis", "database"},
	{"azure.storage", "object-store"},
	{"azure.containerservice", "api-service"},
	{"azure.appservice", "web-app"},
	{"azure.cdn", "web-app"},
	{"azure-native.sql", "database"},
	{"azure-native.dbforpostgresql", "database"},
	{"azure-native.documentdb", "database"},
	{"azure-native.storage", "object-store"},
	{"azure-native.containerservice", "api-service"},
	{"azure-native.web", "web-app"},
	{"azuread.application", "auth-service"},
}

var (
	tfResourceRe = regexp.MustCompile(`(?m)^\s*resource\s+"([a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"`)
	// Bicep: resource <symbolicName> 'Microsoft.X/y@2023-01-01' = { … }
	bicepResourceRe = regexp.MustCompile(`(?m)^\s*resource\s+([A-Za-z0-9_]+)\s+'([^'@]+)@`)
	// ARM template: "type": "Microsoft.X/y"
	armTypeRe = regexp.MustCompile(`"type"\s*:\s*"(Microsoft\.[A-Za-z./]+)"`)
	// Pulumi YAML program: type: aws:s3/bucket:Bucket (or aws:s3:Bucket)
	pulumiYAMLTypeRe = regexp.MustCompile(`(?m)^\s*type:\s*["']?([a-z0-9-]+):([A-Za-z0-9/]+):[A-Za-z0-9]+`)
	// Pulumi TS/Python program: new aws.s3.Bucket("name" / aws.s3.Bucket("name"
	pulumiCodeRe = regexp.MustCompile(`(?:new\s+)?([a-z0-9_-]+)\.([a-z0-9_]+)\.[A-Za-z0-9]+\(\s*["']([A-Za-z0-9._-]+)["']`)
	// Helm values: repository: bitnami/postgresql
	helmRepositoryRe = regexp.MustCompile(`(?m)^\s*repository:\s*["']?([^\s"']+)`)
	// Helm chart dependencies (and other name lists; unmapped names are inert)
	helmDependencyRe = regexp.MustCompile(`(?m)^\s*-\s*name:\s*["']?([a-z0-9-]+)`)
	// Matches YAML (`Type: AWS::X::Y`) and JSON (`"Type": "AWS::X::Y"`) alike:
	// JSON has a quote before the colon, which the old `Type:` form missed —
	// CloudFormation JSON was silently undetectable.
	cfnTypeRe = regexp.MustCompile(`Type["']?\s*:\s*["']?(AWS::[A-Za-z0-9:]+)`)
	k8sKindRe    = regexp.MustCompile(`(?m)^\s*kind:\s*["']?([A-Za-z]+)`)
	imageRe      = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^\s"']+)`)
)

// skipDirs are never walked (vendored code, VCS, the server's own workspace).
var skipDirs = map[string]bool{".git": true, ".appsec": true, "node_modules": true, "vendor": true, ".terraform": true}

// Scan walks dir and returns the detected components, deduplicated by
// name+tech and sorted. A missing dir returns an empty slice, not an error.
func Scan(dir string) ([]Component, error) {
	seen := map[string]Component{}
	add := func(name, tech, source string) {
		if tech == "" || name == "" {
			return
		}
		key := strings.ToLower(name) + "\x00" + tech
		if _, ok := seen[key]; !ok {
			seen[key] = Component{Name: name, Tech: tech, Source: source}
		}
	}

	entries, candidates := 0, 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if entries++; entries > maxWalkEntries {
			return fs.SkipAll
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		lower := strings.ToLower(d.Name())
		isTF := strings.HasSuffix(lower, ".tf")
		isYAML := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
		isJSON := strings.HasSuffix(lower, ".json")
		isBicep := strings.HasSuffix(lower, ".bicep")
		if !isTF && !isYAML && !isJSON && !isBicep {
			return nil
		}
		if candidates++; candidates > maxCandidateFiles {
			return fs.SkipAll
		}
		body := readCapped(path)
		switch {
		case isTF:
			scanTerraform(body, rel, add)
		case isBicep:
			scanBicep(body, rel, add)
		case isCompose(lower):
			scanImages(body, rel, add)
		case lower == "pulumi.yaml" || lower == "pulumi.yml":
			// A YAML program declares resources inline; a code program keeps
			// them in TS/Python entrypoints beside this file.
			scanPulumiYAML(body, rel, add)
			scanPulumiProgramDir(filepath.Dir(path), filepath.Dir(rel), add)
		case isYAML && strings.HasPrefix(lower, "values"):
			// Helm values: image repositories carry the tech.
			scanHelmValues(body, rel, add)
		case lower == "chart.yaml":
			scanHelmChart(body, rel, add)
		case isYAML && strings.Contains(body, "AWS::"):
			// CloudFormation / SAM written as YAML (template.yaml et al.)
			scanCloudFormation(body, rel, add)
		case isYAML:
			scanKubernetes(body, rel, add)
		case strings.Contains(body, "Microsoft."):
			// ARM template (JSON with Azure resource-provider types)
			scanARM(body, rel, add)
		default: // JSON: only CloudFormation is recognized
			scanCloudFormation(body, rel, add)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]Component, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tech != out[j].Tech {
			return out[i].Tech < out[j].Tech
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func scanTerraform(body, rel string, add func(name, tech, source string)) {
	for _, m := range tfResourceRe.FindAllStringSubmatch(body, -1) {
		rtype, rname := m[1], m[2]
		if tech := techForTFResource(rtype); tech != "" {
			add(rname, tech, rel)
		}
	}
}

func techForTFResource(rtype string) string {
	best, bestLen := "", -1
	for _, r := range tfResourceTech {
		if strings.HasPrefix(rtype, r.prefix) && len(r.prefix) > bestLen {
			best, bestLen = r.tech, len(r.prefix)
		}
	}
	return best
}

func scanCloudFormation(body, rel string, add func(name, tech, source string)) {
	if !strings.Contains(body, "AWS::") {
		return
	}
	for _, m := range cfnTypeRe.FindAllStringSubmatch(body, -1) {
		t := m[1]
		for _, r := range cfnTypeTech {
			if strings.Contains(t, r.contains) {
				add(shortType(t), r.tech, rel)
				break
			}
		}
	}
}

func scanBicep(body, rel string, add func(name, tech, source string)) {
	for _, m := range bicepResourceRe.FindAllStringSubmatch(body, -1) {
		symbolic, rtype := m[1], m[2]
		for _, r := range bicepArmTech {
			if strings.Contains(rtype, r.contains) {
				add(symbolic, r.tech, rel)
				break
			}
		}
	}
}

func scanARM(body, rel string, add func(name, tech, source string)) {
	for _, m := range armTypeRe.FindAllStringSubmatch(body, -1) {
		t := m[1]
		for _, r := range bicepArmTech {
			if strings.Contains(t, r.contains) {
				add(shortType(strings.ReplaceAll(t, "/", "::")), r.tech, rel)
				break
			}
		}
	}
}

// scanPulumiYAML handles YAML-runtime Pulumi programs, where Pulumi.yaml
// itself declares resources as type: aws:s3/bucket:Bucket.
func scanPulumiYAML(body, rel string, add func(name, tech, source string)) {
	for _, m := range pulumiYAMLTypeRe.FindAllStringSubmatch(body, -1) {
		provider, module := strings.ToLower(m[1]), strings.ToLower(m[2])
		// aws:s3/bucket → module token "s3"; aws:s3 → "s3"
		module = strings.SplitN(module, "/", 2)[0]
		if tech := techForPulumiModule(provider + "." + module); tech != "" {
			add(module, tech, rel)
		}
	}
}

// scanPulumiProgramDir scans TS/Python entrypoints in the directory that
// holds a Pulumi.yaml — only there, so ordinary application code is never
// pattern-matched. Bounded by the same per-file read cap.
func scanPulumiProgramDir(absDir, relDir string, add func(name, tech, source string)) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		lower := strings.ToLower(e.Name())
		if e.IsDir() || !(strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".py")) {
			continue
		}
		rel := filepath.Join(relDir, e.Name())
		body := readCapped(filepath.Join(absDir, e.Name()))
		for _, m := range pulumiCodeRe.FindAllStringSubmatch(body, -1) {
			provider, module, name := strings.ToLower(m[1]), strings.ToLower(m[2]), m[3]
			provider = strings.ReplaceAll(provider, "_", "-") // azure_native (py) → azure-native
			if tech := techForPulumiModule(provider + "." + module); tech != "" {
				add(name, tech, rel)
			}
		}
	}
}

func techForPulumiModule(key string) string {
	for _, r := range pulumiModuleTech {
		if strings.HasPrefix(key, r.prefix) {
			return r.tech
		}
	}
	return ""
}

// scanHelmValues reads a chart's values file: explicit image: lines plus the
// split repository: form (image.repository: bitnami/postgresql).
func scanHelmValues(body, rel string, add func(name, tech, source string)) {
	scanImages(body, rel, add)
	for _, m := range helmRepositoryRe.FindAllStringSubmatch(body, -1) {
		repo := m[1]
		if strings.Contains(repo, "{{") {
			continue
		}
		lower := strings.ToLower(repo)
		for _, r := range imageTech {
			if strings.Contains(lower, r.contains) {
				add(imageName(repo), r.tech, rel)
				break
			}
		}
	}
}

// scanHelmChart maps Chart.yaml dependency names (postgresql, redis, …)
// through the image table; unrecognized names are inert.
func scanHelmChart(body, rel string, add func(name, tech, source string)) {
	for _, m := range helmDependencyRe.FindAllStringSubmatch(body, -1) {
		name := strings.ToLower(m[1])
		for _, r := range imageTech {
			if strings.Contains(name, r.contains) {
				add(name, r.tech, rel)
				break
			}
		}
	}
}

func scanKubernetes(body, rel string, add func(name, tech, source string)) {
	// A workload kind plus its container image: the image usually reveals the
	// tech (postgres → database); otherwise a Deployment/StatefulSet is a service.
	kinds := k8sKindRe.FindAllStringSubmatch(body, -1)
	if len(kinds) == 0 {
		return
	}
	matchedImage := scanImages(body, rel, add)
	if matchedImage {
		return
	}
	for _, m := range kinds {
		switch m[1] {
		case "Deployment", "StatefulSet", "DaemonSet", "Pod", "ReplicaSet":
			add(baseName(rel), "api-service", rel)
		}
	}
}

func isCompose(name string) bool {
	return name == "docker-compose.yml" || name == "docker-compose.yaml" ||
		name == "compose.yml" || name == "compose.yaml"
}

// scanImages adds a component per recognized container image; returns whether
// any image matched.
func scanImages(body, rel string, add func(name, tech, source string)) bool {
	matched := false
	for _, m := range imageRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(m[1], "{{") {
			continue // Helm-templated image value: no literal tech to read
		}
		img := strings.ToLower(m[1])
		for _, r := range imageTech {
			if strings.Contains(img, r.contains) {
				add(imageName(m[1]), r.tech, rel)
				matched = true
				break
			}
		}
	}
	return matched
}

func readCapped(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		n += len(line) + 1
		if n > maxFileBytes {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func shortType(t string) string {
	parts := strings.Split(t, "::")
	return parts[len(parts)-1]
}
func baseName(rel string) string {
	return strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
}
func imageName(img string) string {
	img = strings.SplitN(img, ":", 2)[0] // drop the tag
	parts := strings.Split(img, "/")
	return parts[len(parts)-1]
}
