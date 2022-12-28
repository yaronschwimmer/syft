package deb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/exp/slices"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

var (
	errEndOfPackages = fmt.Errorf("no more packages to read")
	sourceRegexp     = regexp.MustCompile(`(?P<name>\S+)( \((?P<version>.*)\))?`)
)

func parseDpkgDB(resolver source.FileResolver, env *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	metadata, err := parseDpkgStatus(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to catalog dpkg DB=%q: %w", reader.RealPath, err)
	}

	indirectDependencies := findIndirectDependencies(resolver)

	var pkgs []pkg.Package
	nameToPackage := make(map[string]pkg.Package)
	for _, m := range metadata {
		packageFromMeta := newDpkgPackage(m, reader.Location, resolver, env.LinuxRelease)
		pkgs = append(pkgs, packageFromMeta)
		nameToPackage[packageFromMeta.Name] = packageFromMeta
	}
	relationships := make([]artifact.Relationship, 0)
	for _, m := range metadata {
		to, ok := nameToPackage[m.Package]
		if !ok {
			continue
		}
		for _, dep := range m.Dependencies {
			from, ok := nameToPackage[dep]
			if !ok {
				continue
			}

			relationship := artifact.Relationship{
				From: from,
				To:   to,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, relationship)
		}
		m.IsIndirectDependency = slices.Contains(indirectDependencies, m.Package)
		pkgs = append(pkgs, newDpkgPackage(m, reader.Location, resolver, env.LinuxRelease))
	}

	return pkgs, relationships, nil
}

func findIndirectDependencies(resolver source.FileResolver) []string {
	autoInstalledPackages := make([]string, 0)
	locations, err := resolver.FilesByPath(pkg.ExtendedStatusGlob)
	if err != nil {
		return autoInstalledPackages
	}

	for _, location := range locations {
		contentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			continue
		}

		content, err := io.ReadAll(contentReader)
		internal.CloseAndLogError(contentReader, location.VirtualPath)
		if err != nil {
			continue
		}

		packageInfoItems := strings.Split(string(content), "\n\n")
		for _, packageInfo := range packageInfoItems {
			lines := strings.Split(packageInfo, "\n")
			if strings.Contains(lines[0], "Package") {
				autoInstalledPackage := lines[0][len("Package: "):]
				if len(lines) > 1 && strings.Contains(lines[2], "Auto-Installed") {
					isAutoInstalled := lines[2][len("Auto-Installed: "):]
					if isAutoInstalled == "1" {
						autoInstalledPackages = append(autoInstalledPackages, autoInstalledPackage)
					}
				}
			}
		}
		return autoInstalledPackages
	}
	return nil
}

// parseDpkgStatus is a parser function for Debian DB status contents, returning all Debian packages listed.
func parseDpkgStatus(reader io.Reader) ([]pkg.DpkgMetadata, error) {
	buffedReader := bufio.NewReader(reader)
	var metadata []pkg.DpkgMetadata

	continueProcessing := true
	for continueProcessing {
		entry, err := parseDpkgStatusEntry(buffedReader)
		if err != nil {
			if errors.Is(err, errEndOfPackages) {
				continueProcessing = false
			} else {
				return nil, err
			}
		}
		if entry == nil {
			continue
		}

		metadata = append(metadata, *entry)
	}

	return metadata, nil
}

// parseDpkgStatusEntry returns an individual Dpkg entry, or returns errEndOfPackages if there are no more packages to parse from the reader.
func parseDpkgStatusEntry(reader *bufio.Reader) (*pkg.DpkgMetadata, error) {
	var retErr error
	dpkgFields, err := extractAllFields(reader)
	if err != nil {
		if !errors.Is(err, errEndOfPackages) {
			return nil, err
		}
		if len(dpkgFields) == 0 {
			return nil, err
		}
		retErr = err
	}

	entry := pkg.DpkgMetadata{}
	err = mapstructure.Decode(dpkgFields, &entry)
	if err != nil {
		return nil, err
	}

	if deps, ok := dpkgFields["Depends"]; ok {
		entry.Dependencies = parseDependencies(deps.(string))
	}

	sourceName, sourceVersion := extractSourceVersion(entry.Source)
	if sourceVersion != "" {
		entry.SourceVersion = sourceVersion
		entry.Source = sourceName
	}

	if entry.Package == "" {
		return nil, retErr
	}

	// there may be an optional conffiles section that we should persist as files
	if conffilesSection, exists := dpkgFields["Conffiles"]; exists && conffilesSection != nil {
		if sectionStr, ok := conffilesSection.(string); ok {
			entry.Files = parseDpkgConffileInfo(strings.NewReader(sectionStr))
		}
	}

	if entry.Files == nil {
		// ensure the default value for a collection is never nil since this may be shown as JSON
		entry.Files = make([]pkg.DpkgFileRecord, 0)
	}

	return &entry, retErr
}

func parseDependencies(deps string) []string {
	res := make([]string, 0)
	commaSplit := strings.Split(deps, ",")
	for _, depElem := range commaSplit {
		pipeSplit := strings.Split(depElem, "|")
		for _, dep := range pipeSplit {
			name := strings.Split(strings.TrimSpace(dep), " ")[0]
			res = append(res, name)
		}
	}
	return res
}

func extractAllFields(reader *bufio.Reader) (map[string]interface{}, error) {
	dpkgFields := make(map[string]interface{})
	var key string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return dpkgFields, errEndOfPackages
			}
			return nil, err
		}

		line = strings.TrimRight(line, "\n")

		// empty line indicates end of entry
		if len(line) == 0 {
			// if the entry has not started, keep parsing lines
			if len(dpkgFields) == 0 {
				continue
			}
			break
		}

		switch {
		case strings.HasPrefix(line, " "):
			// a field-body continuation
			if len(key) == 0 {
				return nil, fmt.Errorf("no match for continuation: line: '%s'", line)
			}

			val, ok := dpkgFields[key]
			if !ok {
				return nil, fmt.Errorf("no previous key exists, expecting: %s", key)
			}
			// concatenate onto previous value
			val = fmt.Sprintf("%s\n %s", val, strings.TrimSpace(line))
			dpkgFields[key] = val
		default:
			// parse a new key
			var val interface{}
			key, val, err = handleNewKeyValue(line)
			if err != nil {
				log.Warnf("parsing dpkg status: extracting key-value from line: %s err: %v", line, err)
				continue
			}

			if _, ok := dpkgFields[key]; ok {
				return nil, fmt.Errorf("duplicate key discovered: %s", key)
			}
			dpkgFields[key] = val
		}
	}
	return dpkgFields, nil
}

// If the source entry string is of the form "<name> (<version>)" then parse and return the components, if
// of the "<name>" form, then return name and nil
func extractSourceVersion(source string) (string, string) {
	// special handling for the Source field since it has formatted data
	match := internal.MatchNamedCaptureGroups(sourceRegexp, source)
	return match["name"], match["version"]
}

// handleNewKeyValue parse a new key-value pair from the given unprocessed line
func handleNewKeyValue(line string) (key string, val interface{}, err error) {
	if i := strings.Index(line, ":"); i > 0 {
		key = strings.TrimSpace(line[0:i])
		// mapstruct cant handle "-"
		key = strings.ReplaceAll(key, "-", "")
		val := strings.TrimSpace(line[i+1:])

		// further processing of values based on the key that was discovered
		switch key {
		case "InstalledSize":
			s, err := humanize.ParseBytes(val)
			if err != nil {
				return "", nil, fmt.Errorf("bad installed-size value=%q: %w", val, err)
			}
			return key, int(s), nil
		default:
			return key, val, nil
		}
	}

	return "", nil, fmt.Errorf("cannot parse field from line: '%s'", line)
}
