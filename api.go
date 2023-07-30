package funcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

var initVer, initHex, arkURL, arkBx, arkBody string
var arkHeader http.Header
var (
	jar     = tls_client.NewCookieJar()
	options = []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(360),
		tls_client.WithClientProfile(tls_client.Chrome_112),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}
	client *tls_client.HttpClient
	proxy  = os.Getenv("http_proxy")
)

type kvPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type postBody struct {
	Params []kvPair `json:"params"`
}
type request struct {
	URL      string   `json:"url"`
	Headers  []kvPair `json:"headers,omitempty"`
	PostData postBody `json:"postData,omitempty"`
}
type entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Request         request `json:"request"`
}
type logData struct {
	Entries []entry `json:"entries"`
}
type HARData struct {
	Log logData `json:"log"`
}

func readHAR() {
	file, err := os.ReadFile("chatgpt.har")
	if err != nil {
		fmt.Println(err)
		return
	}
	var harFile HARData
	err = json.Unmarshal(file, &harFile)
	if err != nil {
		println("Error: not a HAR file!")
		return
	}
	var arkReq entry
	for _, v := range harFile.Log.Entries {
		if strings.HasPrefix(v.Request.URL, "https://tcr9i.chat.openai.com/fc/gt2/") {
			arkReq = v
			arkURL = v.Request.URL
			break
		}
	}
	if arkReq.StartedDateTime == "" {
		println("Error: no arkose request!")
		return
	}
	t, err := time.Parse(time.RFC3339, arkReq.StartedDateTime)
	if err != nil {
		panic(err)
	}
	bw := getBw(t.Unix())
	arkHeader = make(http.Header)
	for _, h := range arkReq.Request.Headers {
		// arkHeader except cookie & content-length
		if !strings.EqualFold(h.Name, "content-length") && !strings.EqualFold(h.Name, "cookie") && !strings.HasPrefix(h.Name, ":") {
			arkHeader.Set(h.Name, h.Value)
			if strings.EqualFold(h.Name, "user-agent") {
				bv = h.Value
			}
		}
	}
	arkBody = ""
	for _, p := range arkReq.Request.PostData.Params {
		// arkBody except bda & rnd
		if p.Name == "bda" {
			cipher, err := url.QueryUnescape(p.Value)
			if err != nil {
				panic(err)
			}
			arkBx = Decrypt(cipher, bv+bw)
		} else if p.Name != "rnd" {
			arkBody += "&" + p.Name + "=" + p.Value
		}
	}
}

//goland:noinspection GoUnhandledErrorResult
func init() {
	initVer = "1.5.4"
	initHex = "cd12da708fe6cbe6e068918c38de2ad9" // should be fixed associated with version.
	readHAR()
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	client = &cli
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

//goland:noinspection GoUnhandledErrorResult
func init() {
	cli, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	client = &cli
	proxy := os.Getenv("http_proxy")
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
}

//goland:noinspection GoUnusedExportedFunction
func SetTLSClient(cli *tls_client.HttpClient) {
	client = cli
}

func GetOpenAIToken(puid string, proxy string) (string, string, error) {
	token, err := sendRequest("", puid, proxy)
	return token, initHex, err
}

func GetOpenAITokenWithBx(bx string, puid string, proxy string) (string, string, error) {
	token, err := sendRequest(getBdaWitBx(bx), puid, proxy)
	return token, initHex, err
}

//goland:noinspection SpellCheckingInspection,GoUnhandledErrorResult
func sendRequest(bda string, puid string, proxy string) (string, error) {
	if arkBx == "" || arkBody == "" || len(arkHeader) == 0 {
		return "", errors.New("a valid HAR file required")
	}
	if proxy != "" {
		(*client).SetProxy(proxy)
	}
	if bda == "" {
		bda = getBDA()
	}
	form := "bda=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(bda))) + arkBody + "&rnd=" + strconv.FormatFloat(rand.Float64(), 'f', -1, 64)
	req, _ := http.NewRequest(http.MethodPost, arkURL, strings.NewReader(form))
	req.Header = arkHeader.Clone()
	req.Header.Set("cookie", "_puid="+puid+";")
	resp, err := (*client).Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("status code " + resp.Status)
	}

	type arkoseResponse struct {
		Token string `json:"token"`
	}
	var arkose arkoseResponse
	err = json.NewDecoder(resp.Body).Decode(&arkose)
	if err != nil {
		return "", err
	}
	// Check if rid is empty
	if !strings.Contains(arkose.Token, "sup=1|rid=") {
		return arkose.Token, errors.New("captcha required")
	}

	return arkose.Token, nil
}

//goland:noinspection SpellCheckingInspection
func getBDA() string {
	bx := arkBx
	if bx == "" {
		bx = fmt.Sprintf(bx_template,
			getF(),
			getN(),
			getWh(),
			webglExtensions,
			getWebglExtensionsHash(),
			webglRenderer,
			webglVendor,
			webglVersion,
			webglShadingLanguageVersion,
			webglAliasedLineWidthRange,
			webglAliasedPointSizeRange,
			webglAntialiasing,
			webglBits,
			webglMaxParams,
			webglMaxViewportDims,
			webglUnmaskedVendor,
			webglUnmaskedRenderer,
			webglVsfParams,
			webglVsiParams,
			webglFsfParams,
			webglFsiParams,
			getWebglHashWebgl(),
			initVer,
			initHex,
			getFe(),
			getIfeHash(),
		)
	} else {
		re := regexp.MustCompile(`"key"\:"n","value"\:"\S*?"`)
		bx = re.ReplaceAllString(bx, `"key":"n","value":"`+getN()+`"`)
	}
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}

func getBt() int64 {
	return time.Now().UnixMicro() / 1000000
}

func getBw(bt int64) string {
	return strconv.FormatInt(bt-(bt%21600), 10)
}

func getBdaWitBx(bx string) string {
	bt := getBt()
	bw := getBw(bt)
	return Encrypt(bx, bv+bw)
}
