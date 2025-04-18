package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sitraj/secret-detection/internal/detector"
)

type Server struct {
	detector *detector.Detector
	router   *gin.Engine
}

func NewServer(token string) *Server {
	router := gin.Default()

	// Load HTML templates
	router.LoadHTMLGlob("templates/*")

	// Serve static files
	router.Static("/static", "./static")

	s := &Server{
		detector: detector.NewDetector(token),
		router:   router,
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.GET("/", s.handleIndex)
	s.router.POST("/scan", s.handleScan)
	s.router.POST("/report", s.handleReport)
	s.router.GET("/api-docs", s.handleSwaggerUI)
	s.router.GET("/swagger.yaml", s.handleSwaggerYAML)
}

func (s *Server) Start(addr string) error {
	return s.router.Run(addr)
}

type ScanRequest struct {
	Repository  string `json:"repository" binding:"required"`
	Days        int    `json:"days"`
	ScanCommits bool   `json:"scan_commits"`
	ScanPulls   bool   `json:"scan_pulls"`
}

func (s *Server) handleScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	// Validate repository format
	parts := strings.Split(req.Repository, "/")
	if len(parts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "Invalid repository format. Use 'owner/repo'",
		})
		return
	}

	// Set default values
	if req.Days == 0 {
		req.Days = 30
	}

	ctx := context.Background()
	client := s.detector.Client()
	repo, _, err := client.Repositories.Get(ctx, parts[0], parts[1])
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("Repository not found: %v", err),
		})
		return
	}

	s.detector.SetRepoName(req.Repository)

	// Scan default branch
	if err := s.detector.ScanBranch(ctx, repo, *repo.DefaultBranch); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "error",
			"error":  fmt.Sprintf("Error scanning branch: %v", err),
		})
		return
	}

	// Scan commits if requested
	if req.ScanCommits {
		if err := s.detector.ScanCommits(ctx, repo, req.Days); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": "error",
				"error":  fmt.Sprintf("Error scanning commits: %v", err),
			})
			return
		}
	}

	// Scan pull requests if requested
	if req.ScanPulls {
		if err := s.detector.ScanPullRequests(ctx, repo, req.Days); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"status": "error",
				"error":  fmt.Sprintf("Error scanning pull requests: %v", err),
			})
			return
		}
	}

	c.JSON(http.StatusOK, s.detector.GetResults())
}

func (s *Server) handleReport(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	// First perform the scan
	s.handleScan(c)
	if c.Writer.Status() != http.StatusOK {
		return
	}

	// Generate HTML report
	html := s.generateHTMLReport()
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

func (s *Server) generateHTMLReport() string {
	results := s.detector.GetResults()
	secrets, ok := results["secrets"].([]detector.Secret)
	if !ok {
		return "<html><body><h1>Error generating report</h1></body></html>"
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>GitHub Secret Detection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .secret { margin: 10px 0; padding: 10px; border: 1px solid #ccc; }
        .type { font-weight: bold; color: #e74c3c; }
        .file { font-family: monospace; }
        .line { color: #666; }
    </style>
</head>
<body>
    <h1>GitHub Secret Detection Report</h1>
    <p>Repository: ` + s.detector.RepoName() + `</p>
    <p>Total secrets found: ` + strconv.Itoa(len(secrets)) + `</p>`

	if len(secrets) > 0 {
		html += `<div class="secrets">`
		for _, secret := range secrets {
			html += fmt.Sprintf(`
            <div class="secret">
                <div class="type">%s</div>
                <div class="file">%s (Line %d)</div>
                <div class="line">Context: %s</div>
                <div class="value">%s</div>
            </div>`,
				secret.Type,
				secret.File,
				secret.LineNumber,
				secret.Context,
				secret.MaskedValue,
			)
		}
		html += `</div>`
	} else {
		html += `<p>No secrets found.</p>`
	}

	html += `</body></html>`
	return html
}

func (s *Server) handleSwaggerUI(c *gin.Context) {
	c.HTML(http.StatusOK, "swagger.html", nil)
}

func (s *Server) handleSwaggerYAML(c *gin.Context) {
	c.File("swagger.yaml")
}

func (s *Server) handleIndex(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}
