package credentials

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/internal"
	"gopkg.in/ini.v1"
)

type ProfileCredentialsProvider struct {
	profileName   string
	innerProvider CredentialsProvider
}

type ProfileCredentialsProviderBuilder struct {
	provider *ProfileCredentialsProvider
}

func NewProfileCredentialsProviderBuilder() (builder *ProfileCredentialsProviderBuilder) {
	return &ProfileCredentialsProviderBuilder{
		provider: &ProfileCredentialsProvider{},
	}
}

func (b *ProfileCredentialsProviderBuilder) WithProfileName(profileName string) *ProfileCredentialsProviderBuilder {
	b.provider.profileName = profileName
	return b
}

func (b *ProfileCredentialsProviderBuilder) Build() (provider *ProfileCredentialsProvider) {
	// 优先级：
	// 1. 使用显示指定的 profileName
	// 2. 使用环境变量（ALIBABA_CLOUD_PROFILE）指定的 profileName
	// 3. 兜底使用 default 作为 profileName
	b.provider.profileName = internal.GetDefaultString(b.provider.profileName, os.Getenv("ALIBABA_CLOUD_PROFILE"), "default")

	provider = b.provider
	return
}

func (provider *ProfileCredentialsProvider) getCredentialsProvider(ini *ini.File) (credentialsProvider CredentialsProvider, err error) {
	section, err := ini.GetSection(provider.profileName)
	if err != nil {
		err = errors.New("ERROR: Can not load section" + err.Error())
		return
	}

	value, err := section.GetKey("type")
	if err != nil {
		err = errors.New("ERROR: Can not find credential type" + err.Error())
		return
	}

	switch value.String() {
	case "access_key":
		value1, err1 := section.GetKey("access_key_id")
		value2, err2 := section.GetKey("access_key_secret")
		if err1 != nil || err2 != nil {
			err = errors.New("ERROR: Failed to get value")
			return
		}

		if value1.String() == "" || value2.String() == "" {
			err = errors.New("ERROR: Value can't be empty")
			return
		}

		credentialsProvider = NewStaticAKCredentialsProvider(value1.String(), value2.String())
	case "ecs_ram_role":
		value1, err1 := section.GetKey("role_name")
		if err1 != nil {
			err = errors.New("ERROR: Failed to get value")
			return
		}
		credentialsProvider = NewECSRAMRoleCredentialsProvider(value1.String())
	case "ram_role_arn":
		value1, err1 := section.GetKey("access_key_id")
		value2, err2 := section.GetKey("access_key_secret")
		value3, err3 := section.GetKey("role_arn")
		value4, err4 := section.GetKey("role_session_name")
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			err = errors.New("ERROR: Failed to get value")
			return
		}
		if value1.String() == "" || value2.String() == "" || value3.String() == "" || value4.String() == "" {
			err = errors.New("ERROR: Value can't be empty")
			return
		}
		previous := NewStaticAKCredentialsProvider(value1.String(), value2.String())
		credentialsProvider, err = NewRAMRoleARNCredentialsProvider(previous, value3.String(), value4.String(), 3600, "", "", "")
	default:
		err = errors.New("ERROR: Failed to get credential")
	}
	return
}

func (provider *ProfileCredentialsProvider) GetCredentials() (cc *Credentials, err error) {
	if provider.innerProvider != nil {
		return provider.innerProvider.GetCredentials()
	}

	sharedCfgPath := os.Getenv("ALIBABA_CLOUD_CREDENTIALS_FILE")
	if sharedCfgPath == "" {
		homeDir := getHomePath()
		if homeDir == "" {
			err = fmt.Errorf("cannot found home dir")
			return
		}

		sharedCfgPath = path.Join(homeDir, ".alibabacloud/credentials")
	}

	ini, err := ini.Load(sharedCfgPath)
	if err != nil {
		err = errors.New("ERROR: Can not open file" + err.Error())
		return
	}

	provider.innerProvider, err = provider.getCredentialsProvider(ini)
	if err != nil {
		return
	}

	return provider.innerProvider.GetCredentials()
}