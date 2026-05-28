package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Resource represents a discovered cloud resource with its current live state.
type Resource struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`         // e.g. "aws::ec2::SecurityGroup"
	Region       string            `json:"region"`
	AccountID    string            `json:"account_id"`
	Name         string            `json:"name"`
	Tags         map[string]string `json:"tags"`
	State        json.RawMessage   `json:"state"`        // Full resource state as JSON
	ScannedAt    time.Time         `json:"scanned_at"`
	CloudProvider string           `json:"cloud_provider"` // aws | gcp | azure
}

// CloudClient abstracts multi-cloud resource scanning behind a single interface.
type CloudClient struct {
	provider string
	region   string
	aws      *awsScanner
	// gcp   *gcpScanner   // similarly structured
	// azure *azureScanner
}

func NewCloudClient(provider, region string) (*CloudClient, error) {
	switch provider {
	case "aws":
		s, err := newAWSScanner(region)
		if err != nil {
			return nil, err
		}
		return &CloudClient{provider: "aws", region: region, aws: s}, nil
	case "gcp":
		return &CloudClient{provider: "gcp", region: region}, nil // stub
	case "azure":
		return &CloudClient{provider: "azure", region: region}, nil // stub
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %q", provider)
	}
}

// ScanAll discovers all supported resource types in the configured region.
func (c *CloudClient) ScanAll(ctx context.Context) ([]Resource, error) {
	switch c.provider {
	case "aws":
		return c.aws.scanAll(ctx)
	default:
		return nil, fmt.Errorf("provider %q not fully implemented", c.provider)
	}
}

// ── AWS Scanner ───────────────────────────────────────────────────────────────

type awsScanner struct {
	ec2Client *ec2.Client
	s3Client  *s3.Client
	rdsClient *rds.Client
	iamClient *iam.Client
	region    string
}

func newAWSScanner(region string) (*awsScanner, error) {
	// Uses IRSA / instance profile / env creds — no static keys
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &awsScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		s3Client:  s3.NewFromConfig(cfg),
		rdsClient: rds.NewFromConfig(cfg),
		iamClient: iam.NewFromConfig(cfg),
		region:    region,
	}, nil
}

func (a *awsScanner) scanAll(ctx context.Context) ([]Resource, error) {
	var resources []Resource

	// Scan in parallel across resource types
	type scanResult struct {
		resources []Resource
		err       error
	}
	ch := make(chan scanResult, 4)

	go func() {
		r, err := a.scanSecurityGroups(ctx)
		ch <- scanResult{r, err}
	}()
	go func() {
		r, err := a.scanS3Buckets(ctx)
		ch <- scanResult{r, err}
	}()
	go func() {
		r, err := a.scanEC2Instances(ctx)
		ch <- scanResult{r, err}
	}()
	go func() {
		r, err := a.scanRDSInstances(ctx)
		ch <- scanResult{r, err}
	}()

	for i := 0; i < 4; i++ {
		result := <-ch
		if result.err != nil {
			// Log but don't fail entire scan for one resource type
			continue
		}
		resources = append(resources, result.resources...)
	}

	return resources, nil
}

func (a *awsScanner) scanSecurityGroups(ctx context.Context) ([]Resource, error) {
	resp, err := a.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeSecurityGroups: %w", err)
	}

	resources := make([]Resource, 0, len(resp.SecurityGroups))
	for _, sg := range resp.SecurityGroups {
		state, _ := json.Marshal(sg)
		tags := make(map[string]string)
		for _, t := range sg.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}

		name := ""
		if sg.GroupName != nil {
			name = *sg.GroupName
		}

		resources = append(resources, Resource{
			ID:            deref(sg.GroupId),
			Type:          "aws::ec2::SecurityGroup",
			Region:        a.region,
			Name:          name,
			Tags:          tags,
			State:         state,
			ScannedAt:     time.Now().UTC(),
			CloudProvider: "aws",
		})
	}
	return resources, nil
}

func (a *awsScanner) scanS3Buckets(ctx context.Context) ([]Resource, error) {
	resp, err := a.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("ListBuckets: %w", err)
	}

	resources := make([]Resource, 0, len(resp.Buckets))
	for _, b := range resp.Buckets {
		// For each bucket, get policy and versioning status
		// (simplified here — full impl would fetch ACL, policy, encryption config)
		state, _ := json.Marshal(b)
		resources = append(resources, Resource{
			ID:            deref(b.Name),
			Type:          "aws::s3::Bucket",
			Region:        "global",
			Name:          deref(b.Name),
			State:         state,
			ScannedAt:     time.Now().UTC(),
			CloudProvider: "aws",
		})
	}
	return resources, nil
}

func (a *awsScanner) scanEC2Instances(ctx context.Context) ([]Resource, error) {
	resp, err := a.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeInstances: %w", err)
	}

	var resources []Resource
	for _, reservation := range resp.Reservations {
		for _, inst := range reservation.Instances {
			state, _ := json.Marshal(inst)
			tags := make(map[string]string)
			name := ""
			for _, t := range inst.Tags {
				if t.Key != nil && t.Value != nil {
					tags[*t.Key] = *t.Value
					if *t.Key == "Name" {
						name = *t.Value
					}
				}
			}
			resources = append(resources, Resource{
				ID:            deref(inst.InstanceId),
				Type:          "aws::ec2::Instance",
				Region:        a.region,
				Name:          name,
				Tags:          tags,
				State:         state,
				ScannedAt:     time.Now().UTC(),
				CloudProvider: "aws",
			})
		}
	}
	return resources, nil
}

func (a *awsScanner) scanRDSInstances(ctx context.Context) ([]Resource, error) {
	resp, err := a.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeDBInstances: %w", err)
	}

	resources := make([]Resource, 0, len(resp.DBInstances))
	for _, db := range resp.DBInstances {
		state, _ := json.Marshal(db)
		resources = append(resources, Resource{
			ID:            deref(db.DBInstanceIdentifier),
			Type:          "aws::rds::DBInstance",
			Region:        a.region,
			Name:          deref(db.DBInstanceIdentifier),
			State:         state,
			ScannedAt:     time.Now().UTC(),
			CloudProvider: "aws",
		})
	}
	return resources, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
