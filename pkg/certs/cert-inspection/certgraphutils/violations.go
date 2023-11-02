package certgraphutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
	"k8s.io/apimachinery/pkg/util/sets"
)

const unknownOwner = "Unknown"

var (
	Required = []ViolationFunc{
		GenerateViolationNoOwner,
	}
	All = []ViolationFunc{
		GenerateViolationNoOwner,
		GenerateViolationNoDescription,
	}
)

type Violation struct {
	name                 string
	markdown             []byte
	registry             *certgraphapi.PKIRegistryInfo
	secretCompareFunc    secretCompareFunc
	configMapCompareFunc configMapCompareFunc
}

func (v Violation) getJSONFilePath(parentDir string) string {
	return filepath.Join(parentDir, fmt.Sprintf("%s.json", v.name))
}

func (v Violation) getMarkdownFilePath(parentDir string) string {
	return filepath.Join(parentDir, fmt.Sprintf("%s.md", v.name))
}

func (v Violation) DiffWithExistingJSON(parentDir string) error {
	violationJSONBytes, err := json.MarshalIndent(v.registry, "", "    ")
	if err != nil {
		return err
	}

	existingViolationsJSONBytes, err := os.ReadFile(v.getJSONFilePath(parentDir))
	switch {
	case os.IsNotExist(err): // do nothing
	case err != nil:
		return err
	}
	if diff := cmp.Diff(existingViolationsJSONBytes, violationJSONBytes); len(diff) > 0 {
		return fmt.Errorf(diff)
	}
	return nil
}

func (v Violation) DiffWithExistingMarkdown(parentDir string) error {
	existingViolationsMarkdownBytes, err := os.ReadFile(v.getMarkdownFilePath(parentDir))
	switch {
	case os.IsNotExist(err): // do nothing
	case err != nil:
		return err
	}
	if diff := cmp.Diff(existingViolationsMarkdownBytes, v.markdown); len(diff) > 0 {
		return fmt.Errorf(diff)
	}
	return nil
}

func (v Violation) WriteJSONFile(parentDir string) error {
	violationJSONBytes, err := json.MarshalIndent(v.registry, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.getJSONFilePath(parentDir), violationJSONBytes, 0644)
}

func (v Violation) WriteMarkdownFile(parentDir string) error {
	return os.WriteFile(v.getMarkdownFilePath(parentDir), v.markdown, 0644)
}

type ViolationList []Violation

func (l ViolationList) DiffWithExistingJSON(parentDir string) error {
	var errCombined error
	for _, v := range l {
		if err := v.DiffWithExistingJSON(parentDir); err != nil {
			errCombined = fmt.Errorf("%v\n %s: %v", errCombined, v.name, err)
		}
	}
	return errCombined
}

func (l ViolationList) DiffWithExistingMarkdown(parentDir string) error {
	var errCombined error
	for _, v := range l {
		if err := v.DiffWithExistingMarkdown(parentDir); err != nil {
			errCombined = fmt.Errorf("%v\n %s: %v", errCombined, v.name, err)
		}
	}
	return errCombined
}

func (l ViolationList) WriteJSONFiles(parentDir string) error {
	for _, v := range l {
		if err := v.WriteJSONFile(parentDir); err != nil {
			return err
		}
	}
	return nil
}

func (l ViolationList) WriteMarkdownFiles(dir string) error {
	for _, v := range l {
		if err := v.WriteMarkdownFile(dir); err != nil {
			return err
		}
	}
	return nil
}

type ViolationFunc func(pkiInfo *certgraphapi.PKIRegistryInfo) (Violation, error)

func GenerateViolationList(pkiInfo *certgraphapi.PKIRegistryInfo, funcs ...ViolationFunc) (ViolationList, error) {
	result := ViolationList{}

	for _, violationFunc := range funcs {
		violation, err := violationFunc(pkiInfo)
		if err != nil {
			return result, fmt.Errorf("%s: %v", violation.name, err)
		}
		result = append(result, violation)
	}
	return result, nil
}

type secretCompareFunc func(actual, expected certgraphapi.PKIRegistryCertKeyPairInfo) error
type configMapCompareFunc func(actual, expected certgraphapi.PKIRegistryCertificateAuthorityInfo) error

func diffCertKeyPairOwners(actual, expected certgraphapi.PKIRegistryCertKeyPairInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected JIRA component to be %s, but was %s", expected.OwningJiraComponent, actual.OwningJiraComponent)
	}
	return nil
}

func diffCABundleOwners(actual, expected certgraphapi.PKIRegistryCertificateAuthorityInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected JIRA component to be %s, but was %s", expected.OwningJiraComponent, actual.OwningJiraComponent)
	}
	return nil
}

func GenerateViolationNoOwner(pkiInfo *certgraphapi.PKIRegistryInfo) (Violation, error) {
	registry := &certgraphapi.PKIRegistryInfo{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			registry.CertKeyPairs = append(registry.CertKeyPairs, curr)
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			registry.CertificateAuthorityBundles = append(registry.CertificateAuthorityBundles, curr)
		}
	}

	v := Violation{
		name:                 "ownership-violations",
		registry:             registry,
		secretCompareFunc:    diffCertKeyPairOwners,
		configMapCompareFunc: diffCABundleOwners,
	}

	markdown, err := generateMarkdownNoOwner(pkiInfo)
	if err != nil {
		return v, err
	}
	v.markdown = markdown

	return v, nil
}

func generateMarkdownNoOwner(pkiInfo *certgraphapi.PKIRegistryInfo) ([]byte, error) {
	certsByOwner := map[string][]certgraphapi.PKIRegistryInClusterCertKeyPair{}
	certsWithoutOwners := []certgraphapi.PKIRegistryInClusterCertKeyPair{}
	caBundlesByOwner := map[string][]certgraphapi.PKIRegistryInClusterCABundle{}
	caBundlesWithoutOwners := []certgraphapi.PKIRegistryInClusterCABundle{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			certsWithoutOwners = append(certsWithoutOwners, curr)
			continue
		}
		certsByOwner[owner] = append(certsByOwner[owner], curr)
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			caBundlesWithoutOwners = append(caBundlesWithoutOwners, curr)
			continue
		}
		caBundlesByOwner[owner] = append(caBundlesByOwner[owner], curr)
	}

	md := &bytes.Buffer{}

	fmt.Fprintln(md, "## Missing Owners")
	if len(certsWithoutOwners) > 0 {
		fmt.Fprintln(md, "### Certificates")
		for i, curr := range certsWithoutOwners {
			fmt.Fprintf(md, "%d. ns/%v secret/%v\n\n", i+1, curr.SecretLocation.Namespace, curr.SecretLocation.Name)
			fmt.Fprintf(md, "     **Description:** %v\n", curr.CertKeyInfo.Description)
		}
		fmt.Fprintln(md, "")
	}
	if len(caBundlesWithoutOwners) > 0 {
		fmt.Fprintln(md, "### Certificate Authority Bundles")
		for i, curr := range caBundlesWithoutOwners {
			fmt.Fprintf(md, "%d. ns/%v configmap/%v\n\n", i+1, curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
			fmt.Fprintf(md, "     **Description:** %v\n", curr.CABundleInfo.Description)
		}
		fmt.Fprintln(md, "")
	}

	allOwners := sets.StringKeySet(certsByOwner)
	allOwners.Insert(sets.StringKeySet(caBundlesByOwner).UnsortedList()...)

	fmt.Fprintln(md, "## Known Owners")
	for _, owner := range allOwners.List() {
		fmt.Fprintf(md, "## %v\n", owner)
		certs := certsByOwner[owner]
		if len(certs) > 0 {
			fmt.Fprintln(md, "### Certificates")
			for i, curr := range certs {
				fmt.Fprintf(md, "%d. ns/%v secret/%v\n\n", i+1, curr.SecretLocation.Namespace, curr.SecretLocation.Name)
				fmt.Fprintf(md, "     **Description:** %v\n", curr.CertKeyInfo.Description)
			}
			fmt.Fprintln(md, "")
		}

		caBundles := caBundlesByOwner[owner]
		if len(caBundles) > 0 {
			fmt.Fprintln(md, "### Certificate Authority Bundles")
			for i, curr := range caBundles {
				fmt.Fprintf(md, "%d. ns/%v configmap/%v\n\n", i+1, curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
				fmt.Fprintf(md, "     **Description:** %v\n", curr.CABundleInfo.Description)
			}
			fmt.Fprintln(md, "")
		}
	}

	return md.Bytes(), nil
}

func diffCertKeyPairDescription(actual, expected certgraphapi.PKIRegistryCertKeyPairInfo) error {
	if actual.Description != expected.Description {
		return fmt.Errorf("expected description to be %s, but was %s", expected.Description, actual.Description)
	}
	return nil
}

func diffCABundleDescription(actual, expected certgraphapi.PKIRegistryCertificateAuthorityInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected description to be %s, but was %s", expected.Description, actual.Description)
	}
	return nil
}

func GenerateViolationNoDescription(pkiInfo *certgraphapi.PKIRegistryInfo) (Violation, error) {
	registry := &certgraphapi.PKIRegistryInfo{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		description := curr.CertKeyInfo.Description
		if len(description) == 0 {
			registry.CertKeyPairs = append(registry.CertKeyPairs, curr)
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		description := curr.CABundleInfo.Description
		if len(description) == 0 {
			registry.CertificateAuthorityBundles = append(registry.CertificateAuthorityBundles, curr)
		}
	}

	v := Violation{
		name:                 "description-violations",
		registry:             registry,
		secretCompareFunc:    diffCertKeyPairDescription,
		configMapCompareFunc: diffCABundleDescription,
	}

	markdown, err := generateMarkdownNoDescription(registry)
	if err != nil {
		return v, err
	}
	v.markdown = markdown

	return v, nil
}

func generateMarkdownNoDescription(pkiInfo *certgraphapi.PKIRegistryInfo) ([]byte, error) {
	certsWithoutDescription := map[string]certgraphapi.PKIRegistryInClusterCertKeyPair{}
	caBundlesWithoutDescription := map[string]certgraphapi.PKIRegistryInClusterCABundle{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		description := curr.CertKeyInfo.Description
		if len(description) == 0 && len(owner) != 0 {
			certsWithoutDescription[owner] = curr
			continue
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		description := curr.CABundleInfo.Description
		if len(description) == 0 && len(owner) != 0 {
			caBundlesWithoutDescription[owner] = curr
			continue
		}
	}

	md := &bytes.Buffer{}

	fmt.Fprintln(md, "## Missing descriptions")
	if len(certsWithoutDescription) > 0 {
		fmt.Fprintln(md, "### Certificates")
		for owner, curr := range certsWithoutDescription {
			fmt.Fprintf(md, "1. ns/%v secret/%v\n\n", curr.SecretLocation.Namespace, curr.SecretLocation.Name)
			fmt.Fprintf(md, "     **JIRA component:** %v\n", owner)
		}
		fmt.Fprintln(md, "")
	}
	if len(caBundlesWithoutDescription) > 0 {
		fmt.Fprintln(md, "### Certificate Authority Bundles")
		for owner, curr := range caBundlesWithoutDescription {
			fmt.Fprintf(md, "1. ns/%v configmap/%v\n\n", curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
			fmt.Fprintf(md, "     **JIRA component:** %v\n", owner)
		}
		fmt.Fprintln(md, "")
	}

	return md.Bytes(), nil
}
