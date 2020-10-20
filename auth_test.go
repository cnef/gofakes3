package gofakes3

import (
	"net/http"
	"testing"
)

func TestGoFakeS3_validSignVersion2(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://s3.xxx.com/nks7pc33684-metadata-default/?delimiter=%2F&max-keys=1000&prefix=", nil)

	// Should be set since we are simulating a http server.
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("x-amz-date", "Mon, 19 Oct 2020 08:13:51 GMT")
	r.Header.Set("Authorization", "AWS LNGDC6AG71WZ99SUE7WR:/jOgwV0XlPRdVrqRsP0ZGVDQYd8=")
	cred := Credentials{
		AccessKey: "LNGDC6AG71WZ99SUE7WR",
		SecretKey: "Tf5o41HUOgHqeKmR0sJNaViMHlPiaqNjWddq8SfU",
	}

	err := doesSignV2Match(r, cred)

	t.Log("header", err)
}

func TestGoFakeS3_validSignVersion4(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://s3.xxx.com/nks7pc33684-metadata-default/?delimiter=%2F&max-keys=1000&prefix=", nil)

	r.Header.Set("x-amz-date", "20201020T053334Z")
	r.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=LNGDC6AG71WZ99SUE7WR/20201020/us-east-1/s3/aws4_request,SignedHeaders=host;user-agent;x-amz-content-sha256;x-amz-date, Signature=9a48843b391fabcb075ef9086533669d50842d0c6c6848ed8f148ca7354c6278")
	r.Header.Set("User-Agent", "S3 Browser 8.6.7 https://s3browser.com")

	// Should be set since we are simulating a http server.
	r.RequestURI = r.URL.RequestURI()

	cred := Credentials{
		AccessKey: "LNGDC6AG71WZ99SUE7WR",
		SecretKey: "Tf5o41HUOgHqeKmR0sJNaViMHlPiaqNjWddq8SfU",
	}

	err := doesSignatureMatch("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", r, "", cred)

	t.Log("header", r.Host, err)
}
