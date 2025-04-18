package detector

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"
	"golang.org/x/oauth2"
)

type Secret struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	File        string `json:"file"`
	LineNumber  int    `json:"line_number"`
	Context     string `json:"context"`
	MaskedValue string `json:"masked_value"`
}

type Detector struct {
	client       *github.Client
	patterns     map[string][]*regexp.Regexp
	repoName     string
	secrets      []Secret
	scannedFiles map[string]bool
}

func NewDetector(token string) *Detector {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	patterns := make(map[string][]*regexp.Regexp)

	// API Keys
	patterns["api_key"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9]{32,})['"]?`),
	}

	// AWS Keys
	patterns["aws_key"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)[\s:=]+['"]?([a-zA-Z0-9/+]{40})['"]?`),
	}

	// GitHub Tokens
	patterns["github_token"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(github[_-]?token|gh[_-]?token)[\s:=]+['"]?(ghp_[a-zA-Z0-9]{36})['"]?`),
	}

	// SSH Keys
	patterns["ssh_key"] = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
	}

	return &Detector{
		client:       client,
		patterns:     patterns,
		secrets:      make([]Secret, 0),
		scannedFiles: make(map[string]bool),
	}
}

func (d *Detector) SetRepoName(repoName string) {
	d.repoName = repoName
}

func (d *Detector) ScanBranch(ctx context.Context, repo *github.Repository, branchName string) error {
	opts := &github.RepositoryContentGetOptions{
		Ref: branchName,
	}
	_, dirContent, _, err := d.client.Repositories.GetContents(ctx, *repo.Owner.Login, *repo.Name, "", opts)
	if err != nil {
		return fmt.Errorf("error getting repository contents: %v", err)
	}

	return d.scanContents(ctx, repo, dirContent, branchName)
}

func (d *Detector) ScanCommits(ctx context.Context, repo *github.Repository, daysBack int) error {
	since := time.Now().AddDate(0, 0, -daysBack)
	opts := &github.CommitsListOptions{
		Since: since,
	}

	commits, _, err := d.client.Repositories.ListCommits(ctx, *repo.Owner.Login, *repo.Name, opts)
	if err != nil {
		return fmt.Errorf("error listing commits: %v", err)
	}

	for _, commit := range commits {
		if err := d.scanCommit(ctx, repo, commit); err != nil {
			return err
		}
	}

	return nil
}

func (d *Detector) ScanPullRequests(ctx context.Context, repo *github.Repository, daysBack int) error {
	since := time.Now().AddDate(0, 0, -daysBack)
	opts := &github.PullRequestListOptions{
		State: "all",
	}

	pulls, _, err := d.client.PullRequests.List(ctx, *repo.Owner.Login, *repo.Name, opts)
	if err != nil {
		return fmt.Errorf("error listing pull requests: %v", err)
	}

	for _, pull := range pulls {
		if pull.CreatedAt.After(since) {
			if err := d.scanPullRequest(ctx, repo, pull); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Detector) scanContents(ctx context.Context, repo *github.Repository, contents []*github.RepositoryContent, branchName string) error {
	for _, content := range contents {
		if *content.Type == "dir" {
			_, dirContent, _, err := d.client.Repositories.GetContents(ctx, *repo.Owner.Login, *repo.Name, *content.Path, &github.RepositoryContentGetOptions{
				Ref: branchName,
			})
			if err != nil {
				return err
			}
			if err := d.scanContents(ctx, repo, dirContent, branchName); err != nil {
				return err
			}
		} else {
			if err := d.scanFile(ctx, repo, content, branchName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Detector) scanFile(ctx context.Context, repo *github.Repository, content *github.RepositoryContent, context string) error {
	if d.scannedFiles[*content.Path] {
		return nil
	}

	if *content.Size > 1024*1024 { // Skip files larger than 1MB
		return nil
	}

	fileContent, err := content.GetContent()
	if err != nil {
		return err
	}

	d.checkContentForSecrets(fileContent, *content.Path, context)
	d.scannedFiles[*content.Path] = true
	return nil
}

func (d *Detector) scanCommit(ctx context.Context, repo *github.Repository, commit *github.RepositoryCommit) error {
	commitContent, _, err := d.client.Repositories.GetCommit(ctx, *repo.Owner.Login, *repo.Name, *commit.SHA, nil)
	if err != nil {
		return err
	}

	for _, file := range commitContent.Files {
		if err := d.scanFile(ctx, repo, &github.RepositoryContent{
			Path: file.Filename,
			SHA:  file.SHA,
		}, fmt.Sprintf("commit_%s", *commit.SHA)); err != nil {
			return err
		}
	}

	return nil
}

func (d *Detector) scanPullRequest(ctx context.Context, repo *github.Repository, pull *github.PullRequest) error {
	files, _, err := d.client.PullRequests.ListFiles(ctx, *repo.Owner.Login, *repo.Name, *pull.Number, nil)
	if err != nil {
		return err
	}

	for _, file := range files {
		if err := d.scanFile(ctx, repo, &github.RepositoryContent{
			Path: file.Filename,
			SHA:  file.SHA,
		}, fmt.Sprintf("pr_%d", *pull.Number)); err != nil {
			return err
		}
	}

	return nil
}

func (d *Detector) checkContentForSecrets(content string, filePath string, context string) {
	for secretType, patterns := range d.patterns {
		for _, pattern := range patterns {
			matches := pattern.FindAllStringIndex(content, -1)
			for _, match := range matches {
				secret := content[match[0]:match[1]]
				maskedSecret := d.maskSecret(secret)
				lineNumber := strings.Count(content[:match[0]], "\n") + 1

				d.secrets = append(d.secrets, Secret{
					Type:        secretType,
					Value:       secret,
					File:        filePath,
					LineNumber:  lineNumber,
					Context:     context,
					MaskedValue: maskedSecret,
				})
			}
		}
	}
}

func (d *Detector) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func (d *Detector) GetResults() map[string]interface{} {
	if len(d.secrets) == 0 {
		return map[string]interface{}{
			"status":  "success",
			"message": "No secrets found",
			"secrets": []Secret{},
		}
	}

	return map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Found %d potential secrets", len(d.secrets)),
		"secrets": d.secrets,
	}
}

func (d *Detector) Client() *github.Client {
	return d.client
}

func (d *Detector) RepoName() string {
	return d.repoName
}
