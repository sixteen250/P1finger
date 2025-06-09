package RuleClient

import (
	"regexp"
	"strings"

	"github.com/P001water/P1finger/libs/p1httputils"
)

const (
	Up   = "up"
	Down = "down"
)

func (r *RuleClient) Detect(target string) (DetectRst DetectResult, err error) {

	var P1fingerResps []p1httputils.P1fingerHttpResp

	fixedUrl, err := CheckHttpPrefix(target)
	if err != nil {
		DetectRst = DetectResult{
			OriginUrl: target,
			WebTitle:  "无法访问",
			SiteUp:    Down,
			FingerTag: []string{"unknown proto http/https, try manually"},
		}
		r.RstReqFail.AddElement(DetectRst)
		return
	}

	// 首次访问禁止重定向，手动解析重定向
	resp, p1fingerResp, err := p1httputils.HttpGet(fixedUrl, r.ProxyNoRedirectCilent)
	if err != nil {
		DetectRst = DetectResult{
			OriginUrl:           p1fingerResp.Url,
			OriginUrlStatusCode: p1fingerResp.StatusCode,
			WebTitle:            p1fingerResp.WebTitle,
			SiteUp:              Down,
			FingerTag:           []string{"WebSite down"},
		}
		r.DetectRstTdSafe.AddElement(DetectRst)
		r.RstReqFail.AddElement(DetectRst)
		return
	}
	P1fingerResps = append(P1fingerResps, p1fingerResp)

	var p1fingerRedirectResp p1httputils.P1fingerHttpResp
	redirectType, _, isRedirect := p1httputils.CheckPageRedirect(resp, p1fingerResp)
	if isRedirect {
		switch redirectType {
		case "Location":
			_, p1fingerRedirectResp, err = p1httputils.HttpGet(fixedUrl, r.ProxyClient)
			if err != nil {
				return
			}
			P1fingerResps = append(P1fingerResps, p1fingerRedirectResp)

		case "jsRedirect":
			// todo
		case "VueRoute":
			// todo
		}
	}

	for _, finger := range r.P1FingerPrints.GetElements() {
		for _, matcher := range finger.Matchers {
			matchFlag := false
			for _, targetInfo := range P1fingerResps {
				var content string

				switch matcher.Location {
				case "title":
					content = targetInfo.WebTitle
				case "header":
					if matcher.Type == "regex" {
						re := regexp.MustCompile(strings.Join(matcher.Words, "|")) // 预编译正则
						if re.MatchString(targetInfo.HeaderStr) {
							matchFlag = true
							finger.Name = re.FindString(targetInfo.HeaderStr)
						}
					} else {
						content = targetInfo.HeaderStr
					}
				case "body":
					content = targetInfo.BodyStr
				default:
					continue
				}

				if matcher.Type != "regex" && matchCondition(content, matcher.Words, matcher.Condition) {
					matchFlag = true
				}

				if matchFlag {
					DetectRst.FingerTag = append(DetectRst.FingerTag, finger.Name)
					break
				}
			}

		}
	}

	if len(DetectRst.FingerTag) <= 0 {
		DetectRst = DetectResult{
			OriginUrl:           p1fingerResp.Url,
			OriginUrlStatusCode: p1fingerResp.StatusCode,
			WebTitle:            p1fingerResp.WebTitle,
			SiteUp:              Up,
			FingerTag:           []string{"Target up but missed."},
		}

		// 规则匹配未匹配到，尝试主动路径匹配
		webPathMatch, DetectRstTmp := r.matchWithWebPath(fixedUrl)
		if webPathMatch {
			DetectRst = DetectRstTmp
		} else {
			r.RstMiss.AddElement(DetectRst)
		}

	}

	DetectRst = DetectResult{
		OriginUrl:           p1fingerResp.Url,
		OriginUrlStatusCode: p1fingerResp.StatusCode,
		WebTitle:            p1fingerResp.WebTitle,
		SiteUp:              Up,
		FingerTag:           DetectRst.FingerTag,
	}

	if isRedirect {
		DetectRst.WebTitle = p1fingerRedirectResp.WebTitle
	}

	r.RstShoot.AddElement(DetectRst)

	r.DetectRstTdSafe.AddElement(DetectRst)
	return
}

func (r *RuleClient) matchWithWebPath(fixedUrl string) (matchFlag bool, DetectRst DetectResult) {

	//var DetectRst DetectResult
	var P1fingerResps []p1httputils.P1fingerHttpResp

	for _, finger := range r.P1FingerPrints.GetElements() {
		for _, matcher := range finger.Matchers {
			if matcher.Location == "webPath" {
				fixWebPathUrl := fixedUrl + matcher.Path
				// 首次访问禁止重定向，手动解析重定向
				resp, p1fingerResp, err := p1httputils.HttpGet(fixWebPathUrl, r.ProxyNoRedirectCilent)
				if err != nil {
					DetectRst = DetectResult{
						OriginUrl:           p1fingerResp.Url,
						OriginUrlStatusCode: p1fingerResp.StatusCode,
						WebTitle:            p1fingerResp.WebTitle,
						SiteUp:              Down,
						FingerTag:           []string{"WebSite down"},
					}
					r.DetectRstTdSafe.AddElement(DetectRst)
					r.RstReqFail.AddElement(DetectRst)
					return
				}
				P1fingerResps = append(P1fingerResps, p1fingerResp)

				var P1fingerRedirectResp p1httputils.P1fingerHttpResp
				redirectType, _, isRedirect := p1httputils.CheckPageRedirect(resp, p1fingerResp)
				if isRedirect {
					switch redirectType {
					case "Location":
						//redirectClient := p1httputils.NewRedirectHttpClient()
						_, P1fingerRedirectResp, err = p1httputils.HttpGet(fixWebPathUrl, r.ProxyClient)
						if err != nil {
							return
						}
						P1fingerResps = append(P1fingerResps, P1fingerRedirectResp)

					case "jsRedirect":
						// todo
					case "VueRoute":
						// todo
					}
				}

				for _, fingerResp := range P1fingerResps {
					if matchCondition(fingerResp.BodyStr, matcher.Words, matcher.Condition) {
						DetectRst = DetectResult{
							OriginUrl:           p1fingerResp.Url,
							OriginUrlStatusCode: p1fingerResp.StatusCode,
							WebTitle:            p1fingerResp.WebTitle,
							SiteUp:              Up,
							FingerTag:           []string{finger.Name},
						}
						matchFlag = true
						return
					}
				}
			}
		}
	}

	return
}

func matchCondition(content string, words []string, condition string) bool {
	shooted := 0
	loweredContent := strings.ToLower(content)

	for _, word := range words {
		loweredWord := strings.ToLower(word)
		if strings.Contains(loweredContent, loweredWord) {
			shooted++
			if condition == "or" || condition == "" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}

	return condition == "and" && shooted == len(words)
}
