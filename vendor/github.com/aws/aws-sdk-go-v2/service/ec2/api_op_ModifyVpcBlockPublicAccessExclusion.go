// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Modify VPC Block Public Access (BPA) exclusions. A VPC BPA exclusion is a mode
// that can be applied to a single VPC or subnet that exempts it from the account’s
// BPA mode and will allow bidirectional or egress-only access. You can create BPA
// exclusions for VPCs and subnets even when BPA is not enabled on the account to
// ensure that there is no traffic disruption to the exclusions when VPC BPA is
// turned on.
func (c *Client) ModifyVpcBlockPublicAccessExclusion(ctx context.Context, params *ModifyVpcBlockPublicAccessExclusionInput, optFns ...func(*Options)) (*ModifyVpcBlockPublicAccessExclusionOutput, error) {
	if params == nil {
		params = &ModifyVpcBlockPublicAccessExclusionInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ModifyVpcBlockPublicAccessExclusion", params, optFns, c.addOperationModifyVpcBlockPublicAccessExclusionMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ModifyVpcBlockPublicAccessExclusionOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ModifyVpcBlockPublicAccessExclusionInput struct {

	// The ID of an exclusion.
	//
	// This member is required.
	ExclusionId *string

	// The exclusion mode for internet gateway traffic.
	//
	//   - allow-bidirectional : Allow all internet traffic to and from the excluded
	//   VPCs and subnets.
	//
	//   - allow-egress : Allow outbound internet traffic from the excluded VPCs and
	//   subnets. Block inbound internet traffic to the excluded VPCs and subnets. Only
	//   applies when VPC Block Public Access is set to Bidirectional.
	//
	// This member is required.
	InternetGatewayExclusionMode types.InternetGatewayExclusionMode

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	noSmithyDocumentSerde
}

type ModifyVpcBlockPublicAccessExclusionOutput struct {

	// Details related to the exclusion.
	VpcBlockPublicAccessExclusion *types.VpcBlockPublicAccessExclusion

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationModifyVpcBlockPublicAccessExclusionMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpModifyVpcBlockPublicAccessExclusion{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpModifyVpcBlockPublicAccessExclusion{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "ModifyVpcBlockPublicAccessExclusion"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addSpanRetryLoop(stack, options); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpModifyVpcBlockPublicAccessExclusionValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opModifyVpcBlockPublicAccessExclusion(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opModifyVpcBlockPublicAccessExclusion(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "ModifyVpcBlockPublicAccessExclusion",
	}
}