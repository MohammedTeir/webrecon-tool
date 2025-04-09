package report

import (
	"github.com/webrecon/webrecon-tool/internal/core"
)

// NewReportGenerator creates a new report generator
func NewReportGenerator(results *core.Results) *Generator {
	// Create a dummy target to avoid nil pointer dereference
	dummyTarget, _ := core.NewTarget("example.com")
	
	return &Generator{
		target:  dummyTarget,
		results: results,
	}
}

// GenerateMarkdown generates a markdown report
func (g *Generator) GenerateMarkdown() (string, error) {
	return g.generateMarkdown()
}

// GenerateJSON generates a JSON report
func (g *Generator) GenerateJSON() (string, error) {
	return g.generateJSON()
}
